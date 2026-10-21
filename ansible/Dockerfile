# Runner Ansible conteneurisé : aucun Ansible/Python à installer sur le PC Hôte Windows.
# Contient : docker CLI + plugin compose (pilote le Docker Desktop de l'hôte via son socket)
#            ansible-core (modules builtin uniquement : pas de dépendance Galaxy, fonctionne hors ligne)
FROM docker:29-cli
RUN apk add --no-cache ansible-core py3-requests openssl bash \
 && ansible --version | head -1
WORKDIR /work
ENTRYPOINT ["ansible-playbook"]
