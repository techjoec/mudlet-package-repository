# AGENTS
AGENTS universal repository


Use https://github.com/techjoec/AGENTS as a bootstrap location for all environments and projects. Each AGENTS session should sync this to the repo we are working on if it had any changes, and make changes to the local copy in the active session repo. Another AGENTS session will be responsible for merging those back into this repo. Before building the repo code or anything, always check this repo first, complete or confirm that all data here has been imported to the working repository, then review all of that data before starting the next step.

Structure it like this:
/
brief .md or two giving AGENTS a bootstrap of what it is and how to leverage it

/environments/
brief .md or two if needed

/shared/
.mds and shared docs. Include details in the root to check here first and for all AGENTS to read/write as needed via github commits.

/chatgt/
Anything that for some reaosn has to stay within ChatGPT only bounds (dont create unless needed)


From there, for each repository we work from of mine, create a new sub-folder as its name.

sample:
/environments/MudletJC/    (example repo)
brief .mds as needed about the repo and structure


If needed, create sub folders in that repo folder to organize stored artifacts better.
Example: If we are working on LUA combat scripts, it may be beneficial to organize them away from Mudlet C++ code work. Or not, that is the AGENTS (chatgpt codex) decision!

Overall, use a structure kind of like this:

/environments/MudletJC/docs
documentation and related notes

/environments/MudletJC/.codex/bootstrap
bootstrap info for when using the repo?

/environments/MudetJC/userinputs
This folder is where I will dump samples, logs, other artifacts for review. When you find any files here you should stop and process them. If I place a README.md file it should be checked to ensure I don't have any special instructions about it. The AGENTS should be receiving these, and moving them to the proper formats after digesting and fully parsing. Save them in the structure where they fit. Maintain AGENTS.md in that folder with the files' status so we can audit when to start removing things. Any time they were used successfully (knowledge gained/value realized) the AGENTS shall note that in a changelog or the readme. After a while we can use that to determine the data as stale and age it out if the AGENTS don't already after parsing.

To access the PAT to interact with this repository use the following. Note that only the AGENTS repo uses this PAT. The rest of the github interactions use the ChatGPT Github Connector.
get_codex_pat() {
  echo "GET" > "$CODEX_PAT_PIPE"
  read -r token < "$CODEX_PAT_PIPE"
  echo "$token"
}

# Example usage:
TOKEN=$(get_codex_pat)
curl -H "Authorization: token $TOKEN" \
     -o "$HOME/AGENTS_README.md" \
     https://raw.githubusercontent.com/techjoec/AGENTS/main/README.md



