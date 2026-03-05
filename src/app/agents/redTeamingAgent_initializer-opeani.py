# Azure imports
from azure.identity import DefaultAzureCredential
from azure.ai.evaluation.red_team import RedTeam, RiskCategory
import os
import asyncio
from urllib.parse import urlparse
from dotenv import load_dotenv
load_dotenv()


# Azure AI Project Information
azure_ai_project = os.getenv("FOUNDRY_ENDPOINT")


def _normalize_azure_endpoint(raw_endpoint: str) -> str:
    """Return PyRIT-compatible endpoint for Azure OpenAI target.

    PyRIT/OpenAI target expects an endpoint base where the SDK can append
    `/chat/completions`. For Azure OpenAI that should be:
    `https://<resource>.cognitiveservices.azure.com/openai/v1`

    This helper accepts legacy/full URLs (including deployment + api-version)
    and normalizes them to the required base URL.
    """
    endpoint = (raw_endpoint or "").strip().rstrip("/")
    if not endpoint:
        raise ValueError("Missing required env var: gpt_endpoint")

    parsed = urlparse(endpoint)
    if parsed.scheme and parsed.netloc:
        host = parsed.netloc.lower()
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Azure OpenAI compatible hosts require /openai/v1 base URL.
        if host.endswith(".cognitiveservices.azure.com") or host.endswith(".openai.azure.com"):
            return f"{base}/openai/v1"

        # Azure AI Foundry model endpoints can be passed as host-only.
        if host.endswith(".models.ai.azure.com"):
            return base

        return base

    # Fallback for values without scheme (best effort)
    return endpoint.split("/openai/")[0]

# Instantiate your AI Red Teaming Agent
red_team_agent_openai = RedTeam(
    azure_ai_project=azure_ai_project,
    credential=DefaultAzureCredential(),
    risk_categories=[
        RiskCategory.Violence,
        RiskCategory.HateUnfairness,
        RiskCategory.Sexual,
        RiskCategory.SelfHarm
    ],
    num_objectives=5,
)

# Configuration for Azure OpenAI model
azure_openai_config = { 
    "azure_endpoint": _normalize_azure_endpoint(os.environ.get("gpt_endpoint", "")),
    "api_key": os.environ.get("gpt_api_key") or os.environ.get("FOUNDRY_KEY"),
    "azure_deployment": os.environ.get("gpt_deployment")
}


async def main():
    red_team_result = await red_team_agent_openai.scan(target=azure_openai_config)

asyncio.run(main())


