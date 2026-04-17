from scouter.integrations.openai import wrap_openai

# Framework integrations are lazy-imported to avoid hard dependencies
# on LangChain / CrewAI / AutoGen / Phidata when they are not installed.

__all__ = [
    "wrap_openai",
    "wrap_langchain_tools",
    "wrap_langchain_tool",
    "ScouterToolWrapper",
    "wrap_crewai_tools",
    "wrap_crewai_agent",
    "wrap_autogen_agent",
    "wrap_autogen_functions",
    "wrap_phidata_assistant",
    "wrap_phidata_tools",
]


def __getattr__(name: str):
    """Lazy-load framework integrations on first access."""
    _langchain = {"wrap_langchain_tools", "wrap_langchain_tool", "ScouterToolWrapper"}
    _crewai = {"wrap_crewai_tools", "wrap_crewai_agent"}
    _autogen = {"wrap_autogen_agent", "wrap_autogen_functions"}
    _phidata = {"wrap_phidata_assistant", "wrap_phidata_tools"}

    if name in _langchain:
        from scouter.integrations.langchain import (
            wrap_langchain_tools, wrap_langchain_tool, ScouterToolWrapper,
        )
        return locals()[name]
    if name in _crewai:
        from scouter.integrations.crewai import wrap_crewai_tools, wrap_crewai_agent
        return locals()[name]
    if name in _autogen:
        from scouter.integrations.autogen import wrap_autogen_agent, wrap_autogen_functions
        return locals()[name]
    if name in _phidata:
        from scouter.integrations.phidata import wrap_phidata_assistant, wrap_phidata_tools
        return locals()[name]

    raise AttributeError(f"module 'scouter.integrations' has no attribute {name!r}")
