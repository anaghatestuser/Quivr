# Copyright (c) Lineaje, Inc. All rights reserved.
# Lineaje guardrail helper — inlined once per file (see _import_hint); no
# separate package to install. gr_check() POSTs to GR_SERVICE_URL + "/enforce"
# and fails open (returns `data` unchanged) unless a policy deliberately
# blocks it (GRBlockedError, only on GR_BLOCK_MODE=enforce + an HTTP 403).
class GRBlockedError(Exception):
    def __init__(self, policy_id, reason):
        self.policy_id = policy_id
        self.reason = reason
        super().__init__("Guardrail block for policy %r: %s" % (policy_id, reason))


def gr_check(data, source_type, destination_type, tenant_id="", timeout=5.0, **context):
    import json as _lineaje_json
    import logging as _lineaje_logging
    import os as _lineaje_os
    import urllib.error as _lineaje_urlerr
    import urllib.request as _lineaje_urlreq
    _logger = _lineaje_logging.getLogger("lineaje.gr_client")
    url = _lineaje_os.environ.get("GR_SERVICE_URL", "")  # Lineaje: guardrail endpoint
    if not url:
        return data  # Lineaje: fail-open — GR_SERVICE_URL not configured
    tid = tenant_id or _lineaje_os.environ.get("GR_TENANT_ID", "")
    bearer = _lineaje_os.environ.get("GR_BEARER_TOKEN") or _lineaje_os.environ.get("LINEAJE_PAT_TOKEN") or _lineaje_os.environ.get("LINEAJE_PAT", "")
    hop_label = source_type + "->" + destination_type
    params_key = "out_params" if destination_type == "agent" else "in_params"
    try:
        headers = {"Content-Type": "application/json"}
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        body = {
            "source_type": source_type,
            "destination_type": destination_type,
            params_key: {"data": data},
        }
        for _k, _v in context.items():
            if _v:
                body[_k] = _v
        if tid:
            body["tenant_id"] = tid
        req = _lineaje_urlreq.Request(
            url.rstrip("/") + "/enforce",
            data=_lineaje_json.dumps(body).encode(),
            headers=headers,
            method="POST",
        )
        with _lineaje_urlreq.urlopen(req, timeout=timeout) as resp:
            result = _lineaje_json.loads(resp.read())
    except _lineaje_urlerr.HTTPError as exc:
        if exc.code == 403:
            try:
                detail = _lineaje_json.loads(exc.read()).get("detail", {})
            except Exception:
                detail = {}
            blocked_by = detail.get("blocked_by") or []
            policy_id = blocked_by[0]["policy_id"] if blocked_by else "unknown"
            reason = detail.get("message", "Request denied by policy enforcement.")
            _logger.warning("gr_client[%s]: BLOCKED by policy=%s — %s", hop_label, policy_id, reason)
            if _lineaje_os.environ.get("GR_BLOCK_MODE", "enforce").lower() == "audit":
                return data
            raise GRBlockedError(policy_id, reason)
        _logger.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        return data
    except Exception as exc:
        _logger.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        return data
    if result.get("status") == "escalate":
        _logger.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    return result.get("result", {}).get("data", data)
import datetime
import types
from enum import Enum

from langchain_core.prompts import (
    ChatPromptTemplate,
    HumanMessagePromptTemplate,
    MessagesPlaceholder,
    PromptTemplate,
    SystemMessagePromptTemplate,
)
from langchain_core.prompts.base import BasePromptTemplate


class TemplatePromptName(str, Enum):
    ZENDESK_TEMPLATE_PROMPT = "ZENDESK_TEMPLATE_PROMPT"
    TOOL_ROUTING_PROMPT = "TOOL_ROUTING_PROMPT"
    RAG_ANSWER_PROMPT = "RAG_ANSWER_PROMPT"
    CONDENSE_TASK_PROMPT = "CONDENSE_TASK_PROMPT"
    DEFAULT_DOCUMENT_PROMPT = "DEFAULT_DOCUMENT_PROMPT"
    CHAT_LLM_PROMPT = "CHAT_LLM_PROMPT"
    USER_INTENT_PROMPT = "USER_INTENT_PROMPT"
    UPDATE_PROMPT = "UPDATE_PROMPT"
    SPLIT_PROMPT = "SPLIT_PROMPT"
    ZENDESK_LLM_PROMPT = "ZENDESK_LLM_PROMPT"


def _define_custom_prompts() -> dict[TemplatePromptName, BasePromptTemplate]:
    custom_prompts: dict[TemplatePromptName, BasePromptTemplate] = {}

    today_date = datetime.datetime.now().strftime("%B %d, %Y")

    # ---------------------------------------------------------------------------
    # Prompt for task rephrasing
    # ---------------------------------------------------------------------------
    system_message_template = (
        "Given a chat history and the latest user task "
        "which might reference context in the chat history, "
        "formulate a standalone task which can be understood "
        "without the chat history. Do NOT complete the task, "
        "just reformulate it if needed and otherwise return it as is. "
        "Do not output your reasoning, just the task."
    )

    template_answer = "User task: {task}\n Standalone task:"

    CONDENSE_TASK_PROMPT = ChatPromptTemplate.from_messages(
        [
            SystemMessagePromptTemplate.from_template(system_message_template),
            MessagesPlaceholder(variable_name="chat_history"),
            HumanMessagePromptTemplate.from_template(template_answer),
        ]
    )

    custom_prompts[TemplatePromptName.CONDENSE_TASK_PROMPT] = CONDENSE_TASK_PROMPT

    # ---------------------------------------------------------------------------
    # Prompt for RAG
    # ---------------------------------------------------------------------------
    system_message_template = f"Your name is Quivr. You're a helpful assistant. Today's date is {today_date}. "

    system_message_template += (
        "- When answering use markdown. Use markdown code blocks for code snippets.\n"
        "- Answer in a concise and clear manner.\n"
        "- If no preferred language is provided, answer in the same language as the language used by the user.\n"
        "- You must use ONLY the provided context to complete the task. "
        "Do not use any prior knowledge or external information, even if you are certain of the answer.\n"
        # "- If you cannot provide an answer using ONLY the context provided, do not attempt to answer from your own knowledge."
        # "Instead, inform the user that the answer isn't available in the context and suggest using the available tools {tools}.\n"
        "- Do not apologize when providing an answer.\n"
        "- Don't cite the source id in the answer objects, but you can use the source to complete the task.\n\n"
    )

    context_template = (
        "\n"
        # "- You have access to the following internal reasoning to provide an answer: {reasoning}\n"
        "- You have access to the following files to complete the task (limited to first 20 files): {files}\n"
        "- You have access to the following context to complete the task: {context}\n"
        "- Follow these user instruction when crafting the answer: {custom_instructions}\n"
        "- These user instructions shall take priority over any other previous instruction.\n"
        # "- Remember: if you cannot provide an answer using ONLY the provided context and CITING the sources, "
        # "inform the user that you don't have the answer and consider if any of the tools can help answer the question.\n"
        # "- Explain your reasoning about the potentiel tool usage in the answer.\n"
        # "- Only use binded tools to answer the question.\n"
        # "OFFER the user the possibility to ACTIVATE a relevant tool among "
        # "the tools which can be activated."
        # "Tools which can be activated: {tools}. If any of these tools can help in providing an answer "
        # "to the user question, you should offer the user the possibility to activate it. "
        # "Remember, you shall NOT use the above tools, ONLY offer the user the possibility to activate them.\n"
    )

    template_answer = (
        "Original task: {task}\n"
        "Rephrased and contextualized task: {rephrased_task}\n"
        "Remember, you shall complete ALL tasks.\n"
        "Remember: if you cannot provide an answer using ONLY the provided context and CITING the sources, "
        "just answer that you don't have the answer.\n"
        "If the provided context contains contradictory or conflicting information, state so providing the conflicting information.\n"
    )

    RAG_ANSWER_PROMPT = ChatPromptTemplate.from_messages(
        [
            SystemMessagePromptTemplate.from_template(system_message_template),
            MessagesPlaceholder(variable_name="chat_history"),
            SystemMessagePromptTemplate.from_template(context_template),
            HumanMessagePromptTemplate.from_template(template_answer),
        ]
    )
    custom_prompts[TemplatePromptName.RAG_ANSWER_PROMPT] = RAG_ANSWER_PROMPT

    # ---------------------------------------------------------------------------
    # Prompt for formatting documents
    # ---------------------------------------------------------------------------
    DEFAULT_DOCUMENT_PROMPT = PromptTemplate.from_template(
        template="Filename: {original_file_name}\nSource: {index} \n {page_content}"
    )
    custom_prompts[TemplatePromptName.DEFAULT_DOCUMENT_PROMPT] = DEFAULT_DOCUMENT_PROMPT

    # ---------------------------------------------------------------------------
    # Prompt for chatting directly with LLMs, without any document retrieval stage
    # ---------------------------------------------------------------------------
    system_message_template = (
        f"Your name is Quivr. You're a helpful assistant. Today's date is {today_date}."
    )
    system_message_template += """
    If not None, also follow these user instructions when answering: {custom_instructions}
    """

    template_answer = """
    User Task: {task}
    Answer:
    """
    CHAT_LLM_PROMPT = ChatPromptTemplate.from_messages(
        [
            SystemMessagePromptTemplate.from_template(system_message_template),
            MessagesPlaceholder(variable_name="chat_history"),
            HumanMessagePromptTemplate.from_template(template_answer),
        ]
    )
    custom_prompts[TemplatePromptName.CHAT_LLM_PROMPT] = CHAT_LLM_PROMPT

    # ---------------------------------------------------------------------------
    # Prompt to understand the user intent
    # ---------------------------------------------------------------------------
    system_message_template = (
        "Given the following user input, determine the user intent, in particular "
        "whether the user is providing instructions to the system or is asking the system to "
        "complete a task:\n"
        "    - if the user is providing direct instructions to modify the system behaviour (for instance, "
        "'Can you reply in French?' or 'Answer in French' or 'You are an expert legal assistant' "
        "or 'You will behave as...'), the user intent is 'prompt';\n"
        "    - in all other cases (asking questions, asking for summarising a text, asking for translating a text, ...), "
        "the intent is 'task'.\n"
    )

    template_answer = "User input: {task}"

    USER_INTENT_PROMPT = ChatPromptTemplate.from_messages(
        [
            SystemMessagePromptTemplate.from_template(system_message_template),
            HumanMessagePromptTemplate.from_template(template_answer),
        ]
    )
    custom_prompts[TemplatePromptName.USER_INTENT_PROMPT] = USER_INTENT_PROMPT

    # ---------------------------------------------------------------------------
    # Prompt to create a system prompt from user instructions
    # ---------------------------------------------------------------------------
    system_message_template = (
        "- Given the following user instruction, current system prompt, list of available tools "
        "and list of activated tools, update the prompt to include the instruction and decide which tools to activate.\n"
        "- The prompt shall only contain generic instructions which can be applied to any user task or question.\n"
        "- The prompt shall be concise and clear.\n"
        "- If the system prompt already contains the instruction, do not add it again.\n"
        "- If the system prompt contradicts ther user instruction, remove the contradictory "
        "statement or statements in the system prompt.\n"
        "- You shall return separately the updated system prompt and the reasoning that led to the update.\n"
        "- If the system prompt refers to a tool, you shall add the tool to the list of activated tools.\n"
        "- If no tool activation is needed, return empty lists.\n"
        "- You shall also return the reasoning that led to the tool activation.\n"
        "- Current system prompt: {system_prompt}\n"
        "- List of available tools: {available_tools}\n"
        "- List of activated tools: {activated_tools}\n\n"
    )

    template_answer = "User instructions: {instruction}\n"

    UPDATE_PROMPT = ChatPromptTemplate.from_messages(
        [
            SystemMessagePromptTemplate.from_template(system_message_template),
            HumanMessagePromptTemplate.from_template(template_answer),
        ]
    )
    custom_prompts[TemplatePromptName.UPDATE_PROMPT] = UPDATE_PROMPT

    # ---------------------------------------------------------------------------
    # Prompt to split the user input into multiple questions / instructions
    # ---------------------------------------------------------------------------
    system_message_template = (
        "Given a chat history and the user input, split and rephrase the input into instructions and tasks.\n"
        "- Instructions direct the system to behave in a certain way or to use specific tools: examples of instructions are "
        "'Can you reply in French?', 'Answer in French', 'You are an expert legal assistant', "
        "'You will behave as...', 'Use web search').\n"
        "- You shall collect and condense all the instructions into a single string.\n"
        "- The instructions shall be standalone and self-contained, so that they can be understood "
        "without the chat history. If no instructions are found, return an empty string.\n"
        "- Instructions to be understood may require considering the chat history.\n"
        "- Tasks are often questions, but they can also be summarisation tasks, translation tasks, content generation tasks, etc.\n"
        "- Tasks to be understood may require considering the chat history.\n"
        "- If the user input contains different tasks, you shall split the input into multiple tasks.\n"
        "- Each splitted task shall be a standalone, self-contained task which can be understood "
        "without the chat history. You shall rephrase the tasks if needed.\n"
        "- If no explicit task is present, you shall infer the tasks from the user input and the chat history.\n"
        "- Do NOT try to solve the tasks or answer the questions, "
        "just reformulate them if needed and otherwise return them as is.\n"
        "- Remember, you shall NOT suggest or generate new tasks.\n"
        "- As an example, the user input 'What is Apple? Who is its CEO? When was it founded?' "
        "shall be split into a list of tasks ['What is Apple?', 'Who is the CEO of Apple?', 'When was Apple founded?']\n"
        "- If no tasks are found, return the user input as is in the task list.\n"
    )

    template_answer = "User input: {user_input}"

    SPLIT_PROMPT = ChatPromptTemplate.from_messages(
        [
            SystemMessagePromptTemplate.from_template(system_message_template),
            MessagesPlaceholder(variable_name="chat_history"),
            HumanMessagePromptTemplate.from_template(template_answer),
        ]
    )
    custom_prompts[TemplatePromptName.SPLIT_PROMPT] = SPLIT_PROMPT

    # ---------------------------------------------------------------------------
    # Prompt to grade the relevance of an answer and decide whather to perform a web search
    # ---------------------------------------------------------------------------
    system_message_template = (
        "Given the following tasks you shall determine whether all tasks can be "
        "completed fully and in the best possible way using the provided context and chat history. "
        "You shall:\n"
        "- Consider each task separately,\n"
        "- Determine whether the context and chat history contain "
        "all the information necessary to complete the task.\n"
        "- If the context and chat history do not contain all the information necessary to complete the task, "
        "consider ONLY the list of tools below and select the tool most appropriate to complete the task.\n"
        "- If no tools are listed, return the tasks as is and no tool.\n"
        "- If no relevant tool can be selected, return the tasks as is and no tool.\n"
        "- Do not propose to use a tool if that tool is not listed among the available tools.\n"
    )

    context_template = "Context: {context}\n {activated_tools}\n"

    template_answer = "Tasks: {tasks}\n"

    TOOL_ROUTING_PROMPT = ChatPromptTemplate.from_messages(
        [
            SystemMessagePromptTemplate.from_template(system_message_template),
            MessagesPlaceholder(variable_name="chat_history"),
            SystemMessagePromptTemplate.from_template(context_template),
            HumanMessagePromptTemplate.from_template(template_answer),
        ]
    )

    custom_prompts[TemplatePromptName.TOOL_ROUTING_PROMPT] = TOOL_ROUTING_PROMPT

    system_message_zendesk_template = """
    You are a Customer Service Agent using Zendesk. You are answering a client query.
    You will be provided with the users metadata, ticket metadata and ticket history which can be used to answer the query.
    You will also have access to the most relevant similar tickets and additional information sometimes such as API calls.
    Never add something in brackets that needs to be filled like [your name], [your email], etc. 
    Do NOT invent information that was not present in previous tickets or in user metabadata or ticket metadata or additional information.
    Always prioritize information from the most recent tickets, especially if they are contradictory.
    
    Here is the current time: {current_time} UTC
    
    Here are default instructions that can be ignored if they are contradictory to the <instructions from me> section:
    <default instructions>
    - Don't be too verbose, use the same amount of details as in similar tickets.
    - Use the same tone, format, structure and lexical field as in similar tickets agent responses.
    - The text must be correctly formatted with paragraphs, bold, italic, etc so it is easier to read.
    - Maintain consistency in terminology used in recent tickets.
    - Answer in the same language as the user.
    - Don't add a signature at the end of the answer, it will be added once the answer is sent.
    </default instructions>
    
    
    Here are instructions that you MUST follow and prioritize over the <default instructions> section:
    <instructions from me>
    {guidelines}
    </instructions from me>
    """

    user_prompt_template = """
    Here is information about the user that can help you to answer:
    <user_metadata>
    {user_metadata}
    </user_metadata>

    Here are metadata on the current ticket that can help you to answer:
    <ticket_metadata>
    {ticket_metadata}
    </ticket_metadata>


    Here are the most relevant similar tickets that can help you to answer:
    <similar_tickets>
    {similar_tickets}
    </similar_tickets>

    Here are the current ticket history:
    <ticket_history>
    {ticket_history}
    </ticket_history>

    Here are additional information that can help you to answer:
    <additional_information>
    {additional_information}
    </additional_information>

    Here is the client question to which you must answer:
    <client_query>
    {client_query}
    </client_query>
 
    Based on the informations provided, answer directly with the message to send to the customer, ready to be sent:
    Answer:"""

    ZENDESK_TEMPLATE_PROMPT = ChatPromptTemplate.from_messages(
        [
            SystemMessagePromptTemplate.from_template(system_message_zendesk_template),
            HumanMessagePromptTemplate.from_template(user_prompt_template),
        ]
    )
    custom_prompts[TemplatePromptName.ZENDESK_TEMPLATE_PROMPT] = ZENDESK_TEMPLATE_PROMPT

    system_message_template = "{enforced_system_prompt}"

    template_answer = """
    <draft answer>
    {task}
    <draft answer>
    Stick closely to this draft answer. Assume that the draft answer informations are correct, and do not try to outsmart him/her.
    Respond directly with the message to send to the customer, ready to be sent:

    Answer:
    """
    ZENDESK_LLM_PROMPT = ChatPromptTemplate.from_messages(
        [
            SystemMessagePromptTemplate.from_template(system_message_template),
            MessagesPlaceholder(variable_name="chat_history"),
            HumanMessagePromptTemplate.from_template(template_answer),
        ]
    )
    custom_prompts[TemplatePromptName.ZENDESK_LLM_PROMPT] = ZENDESK_LLM_PROMPT

    try:
        custom_prompts = gr_check(custom_prompts, "agent", "user_interface", site_id='site:sha256:71dc144f983bfeab2d152e4dfe86fd2b2569a94cac4f605a5cc31e3927697d5d')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError":
            raise
        custom_prompts = custom_prompts
        import logging as _lineaje_logging
        _lineaje_logging.getLogger("lineaje.gr_client").warning(
            "Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked"
        )
    return custom_prompts


_templ_registry: dict[TemplatePromptName, BasePromptTemplate] = _define_custom_prompts()

custom_prompts = types.MappingProxyType(_templ_registry)
