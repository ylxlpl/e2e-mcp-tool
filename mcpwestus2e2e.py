# Import necessary libraries

import os, time
import argparse
from typing import List, Dict, Optional
from pathlib import Path
from azure.ai.projects import AIProjectClient
from azure.identity import DefaultAzureCredential
from azure.ai.agents.models import (
    ListSortOrder,
    McpTool,
    RequiredMcpToolCall,
    SubmitToolApprovalAction,
    ToolApproval,
)

RUN_ACTIVE_STATES = {"queued", "in_progress", "requires_action"}

def load_env(env_path: Path) -> None:
    """Load environment variables from a .env file if present (simple key=value parser)."""
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        os.environ.setdefault(key, val)

def build_mcp_tool_config(url: str, label: str, connection_name: str) -> Dict[str, str]:
    return {
        "type": "mcp",
        "server_url": url,
        "server_label": label,
        "server_authentication": {
            "type": "connection",
            "connection_name": connection_name,
        },
    }

def merge_tools(existing: List[Dict], new_tool: Dict) -> List[Dict]:
    #return [new_tool]
    labels = {t.get("server_label") for t in existing if t.get("type") == "mcp"}
    if new_tool.get("server_label") in labels:
        return existing
    return existing + [new_tool]

def create_agent_with_mcp_tool(project_client: AIProjectClient, mcp_tool_config: Dict[str, str]):
    with project_client:
        agents_client = project_client.agents
        
        # Create a new agent.
        agent = agents_client.create_agent(
            model="gpt-4o",
            name="my-mcp-agent",
            instructions="You are a helpful agent that can use MCP tools to assist users. Use the available MCP tools to answer questions and perform tasks.",
            tools=[mcp_tool_config],
        )
        print(f"Created agent with ID: {agent.id}")
    return agent

def print_conversation(agents_client, thread_id: str) -> None:
    messages = agents_client.messages.list(thread_id=thread_id, order=ListSortOrder.ASCENDING)
    print("\nConversation:\n" + "-" * 50)
    for msg in messages:
        if msg.text_messages:
            last_text = msg.text_messages[-1]
            print(f"{msg.role.upper()}: {last_text.text.value}\n" + "-" * 50)


def process_run_and_poll(agents_client, thread_id: str, run, mcp_headers: Optional[Dict[str, str]] = None):
    print(f"Created run, ID: {run.id}")
    while run.status in RUN_ACTIVE_STATES:
        time.sleep(1)
        run = agents_client.runs.get(thread_id=thread_id, run_id=run.id)

        if run.status == "requires_action" and isinstance(run.required_action, SubmitToolApprovalAction):
            tool_calls = run.required_action.submit_tool_approval.tool_calls or []
            if not tool_calls:
                print("No tool calls provided - cancelling run")
                agents_client.runs.cancel(thread_id=thread_id, run_id=run.id)
                break

            tool_approvals: List[ToolApproval] = []
            for tool_call in tool_calls:
                if isinstance(tool_call, RequiredMcpToolCall):
                    try:
                        print(f"Approving tool call: {tool_call.id}")
                        tool_approvals.append(
                            ToolApproval(
                                tool_call_id=tool_call.id,
                                approve=True,
                                headers=mcp_headers,
                            )
                        )
                    except Exception as e:
                        print(f"Error approving tool_call {tool_call.id}: {e}")

            if tool_approvals:
                agents_client.runs.submit_tool_outputs(
                    thread_id=thread_id, run_id=run.id, tool_approvals=tool_approvals
                )
                print(f"Submitted {len(tool_approvals)} tool approval(s)")

        print(f"Current run status: {run.status}")

    print(f"Run completed with status: {run.status}")
    if run.status == "failed":
        print(f"Run failed: {run.last_error}")
    print_conversation(agents_client, thread_id)

def trigger_agent_run(agents_client, existing_agent) -> (str, 'Run'):

    mcp_tool_resources = {
        "mcp": [
            {
                "server_label": os.environ.get("MCP_SERVER_LABEL", "my_mcp_server"),
                "require_approval": "never"
            }
        ]
    }

    # Create thread for communication
    thread = agents_client.threads.create()
    print(f"Created thread, ID: {thread.id}")

    # Parse command-line args for interactive use
    parser = argparse.ArgumentParser(description="Interact with MCP agent round-by-round")
    parser.add_argument("-p", "--prompt", help="One-off prompt to send (non-interactive)")
    parser.add_argument("--once", action="store_true", help="Exit after sending one prompt")
    args = parser.parse_args()

    # Interaction loop: use --prompt for one-off, otherwise interactive round-by-round
    while True:
        if args.prompt:
            user_input = args.prompt
            # clear so next loop becomes interactive
            args.prompt = None
        else:
            try:
                user_input = input("You: ")
            except EOFError:
                break

        if not user_input or user_input.strip().lower() in ("exit", "quit"):
            print("Exiting interactive session")
            break

        # create and send message
        message = agents_client.messages.create(
            thread_id=thread.id,
            role="user",
            content=user_input,
        )
        print(f"Created message, ID: {message.id}")

        # create run and process
        run = agents_client.runs.create(
            thread_id=thread.id,
            agent_id=existing_agent.id,
            tool_resources=mcp_tool_resources,
        )
        process_run_and_poll(agents_client, thread.id, run)

        if args.once:
            break

    print_conversation(agents_client, thread.id)

def main():
    load_env(Path(__file__).parent / ".env")
    args = argparse.ArgumentParser().parse_args()  # add your flags

    endpoint = os.environ.get("AI_PROJECT_ENDPOINT")
    project_client = AIProjectClient(endpoint=endpoint, credential=DefaultAzureCredential())

    with project_client:
        agents_client = project_client.agents
        existing_agent = agents_client.get_agent("{YOUR_AGENT_ID}")

        mcp_tool_config = build_mcp_tool_config(
            url=os.environ.get("MCP_SERVER_URL", "https://e2e.azurewebsites.net/api/mcp"),
            label=os.environ.get("MCP_SERVER_LABEL", "my_mcp_server"),
            connection_name=os.environ.get("MCP_CONNECTION_NAME", "blobagenticidentity"),
        )

        existing_agent = agents_client.update_agent(existing_agent.id, tools=merge_tools(existing_agent.tools or [], mcp_tool_config))
        print(f"Updated tools: {existing_agent.tools}")

        trigger_agent_run(agents_client, existing_agent)


if __name__ == "__main__":
    main()