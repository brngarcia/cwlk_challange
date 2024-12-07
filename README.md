# cwlk_challange

<h1>1. Contextualização </h1>

Ao receber o desafio, encontrei um arquivo de log, contendo requisições HTTP/HTTPS. Estruturado no formado CSV.
O conteudo do arquivo contia 30 mil entradas, as quais se referem dos dias 04-nov a 14-nov. <br> </br>
Contendo os seguintes atributos:

| ClientRequestHost	| ClientRequestMethod	| ClientRequestURI	| EdgeStartTimestamp	| ZoneName |	ClientASN	| ClientCountry | ClientDeviceType | ClientSrcPort	| ClientRequestBytes |	ClientRequestPath	| ClientRequestReferer |	ClientRequestScheme |	| ClientRequestUserAgent |


<h1>2. Configuração do Ambiente</h1>
Ao me deparar com o log, meu primeiro pensamento foi de analisar com ferramentas simples, como loganalyzer ou até mesmo excel. Entretanto, notei que poderia utilizar alguma ferramenta mais robusta para enriquecer a analise. <br> </br>

Para realizar a analise dos dados, optei por subir algumas ferramentas via docker, para que, auxiliem no processo de analise.
Optei por utilizar a stack do ELK, subindo um Elastic Search + Kibana.

Abaixo a configuração **Simplificada** da instalação:

<h2>Configuraçao Elastic Docker</h2>

> docker pull docker.elastic.co/elasticsearch/elasticsearch:8.16.1

![image](https://github.com/user-attachments/assets/17570440-ea0e-4098-92bb-6346d8a3a672)

> docker network create elastic

![image](https://github.com/user-attachments/assets/6fbfbd86-a12e-426e-b913-263ed9add5cb)

> docker run --name es01 --net elastic -p 9200:9200 -it -m 1GB docker.elastic.co/elasticsearch/elasticsearch:8.16.1

> docker run --name es01 --net elastic -p 9200:9200 -it -m 6GB -e "xpack.ml.use_auto_machine_memory_percent=true" docker.elastic.co/elasticsearch/elasticsearch:8.16.1
> docker exec -it es01 /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic
> docker exec -it es01 /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana

![image](https://github.com/user-attachments/assets/c2483fc7-e2c6-4e54-98f0-c130cc9c3de4)

Validando via web:

![image](https://github.com/user-attachments/assets/b95049f6-a917-4e0f-aeea-ca5467e5d89f)


Elastic no ar! _(Agora vamos para Kibana)_
![image](https://github.com/user-attachments/assets/07dc5321-7831-45ba-b3de-54c80c5ac836)


<h2>Configurações Kibana Docker</h2>

Após realizar a configuração do ambiente, e subir as ferramentas que vão auxiliar na analise, foi realizado um teste para garantir que o ambiente estivesse funcional

> docker pull docker.elastic.co/kibana/kibana:8.16.1

![image](https://github.com/user-attachments/assets/e39ee6ad-ac7a-499f-8fd0-86396672a0c1)

> wget https://artifacts.elastic.co/cosign.pub
cosign verify --key cosign.pub docker.elastic.co/kibana/kibana:8.16.1

> docker run --name kib01 --net elastic -p 5601:5601 docker.elastic.co/kibana/kibana:8.16.1

![image](https://github.com/user-attachments/assets/771a9fbf-a005-43e2-a916-cb0cf2a05251)

**ELK no ar!!!!**

![image](https://github.com/user-attachments/assets/2b43d05d-3c54-46b4-90b6-5d1a908d245e)

De forma resumida, essa foi a construção do ambiente. Utilizei Docker que facilita muito e tem grandes ganhos na velocidade de configuração.


<h1>2. Analise dos Dados </h1>

De forma inicial, realizei o upload do arquivo de log para o Elastic:

![image](https://github.com/user-attachments/assets/c2ec1422-49d1-4885-b1fe-3548d28d1eca)

O qual foi processado sem a necessidade de criação de parsers customizados:

![image](https://github.com/user-attachments/assets/7a17f578-c9a6-43f6-8ac7-2310a499482b)

Resultando em dados estruturados, auxiliando o engenheiro na analise do log e comportamento do ambiente:

![image](https://github.com/user-attachments/assets/e7b0e5e3-65f0-4db6-94b8-098305c9e088)

<h2>Detecção des atividade suspeitas</h2>
Logo após a insersão dos dados no ELK, foi possível a olho nu, detectar algumas atividades suspeitas, sem aplicar filtros ou querys elaboradas. 

Como uma tentativa de **XSS**:

![image](https://github.com/user-attachments/assets/6cb3e092-0470-41ca-9647-41eae286a7e5)

É possível identificar o ataque pelo header **ClientRequestPath**, o qual ajuda a identificar a path solicitada na requisição.
Outro exemplo de ataque, foi um path traversal identificado antes mesmo de aplicar os filtros e realizar uma analise mais detalhada:

![image](https://github.com/user-attachments/assets/e4ad1460-df2d-42f5-b9fb-bac39babd11d)


Com este atributo foi possível identificar inumeras requisções maliciosas:

![image](https://github.com/user-attachments/assets/25520010-cc29-4c7e-89e7-db6138e6d147)

Podendo classificadas nas seguintes categorias:

--- **Directory Traversal / Path Traversal** ---

/../../../../../../../../../../etc/shadow 

/../../../etc/passwd

/.git/config 

/../../boot.ini

--- **XSS (Cross-Site Scripting)** ---

/<iframe src=''javascript:alert(1)''></iframe>

/<img src=''x' onerror='alert(1)''>

/<marquee><img 'src=1 onerror=alert(1)'></marquee>

/<meta http-equiv='refresh' content='0

/<script>alert('XSS')</script>


--- **SQL Injection** ---

/admin.php?user=admin&password=admin 

/api/v1/users?search= _(Aqui pode ser um falso positivo, entretanto acredito que faça sentido incluir na analise)_
<br> </br>


--- **Remote Code Execution (RCE)** --- _(Classifico como RCE pois acredito que o atacante optaria por tentar explorar algum shell reverso ou RCE direto, via essas chamadas)_

/shell.php?cmd=cat%20/etc/passwd 

/../../../windows/system32/cmd.exe

Após realizar executar a triagem e analise inicial, foram identificadas 1.375 requisições maliciosas, a qual montei a seguinte query no Elastic:
> ClientRequestPath : "/\";!--\"<XSS>=&{()}" or "/../../../../../../../../../../etc/shadow" or "/%00%01%02%03%04%05%06%07" or "/../../../../../../../../../../etc/shadow" or "/../../../../windows/system32/cmd.exe" or "/../../../etc/passwd" or "/../../../windows/win.ini" or "/../../boot.ini" or "/.git/config" or "/<iframe src=''javascript:alert(1)'></iframe>" or "/<img src='x'' onerror='alert(1)'>" or "/<marquee><img 'src=1 onerror=alert(1)></marquee>" or  "/<meta http-equiv='refresh' content='0" or "/<script>alert('XSS')</script>" or "/admin.php?user=admin&password=admin" or "/api/v1/users?search=" or "/shell.php?cmd=cat%20/etc/passwd"

Dentro desse volume de requisições **maliciosas**, foi possível identificar alguns itens que poderiamos utilizar para a remediação, como por exemplo, o alto volume de requisições enviadas pelo AS numero **396982** totalizando **37%** do volume total.
![image](https://github.com/user-attachments/assets/5be9b566-7cbb-42b5-bd7d-1ceca6134846)

**AS Details:** (https://ipinfo.io/AS396982) 
![image](https://github.com/user-attachments/assets/bc203b4d-9686-4290-b8b6-6667e4f4d674)


Embora esse AS tenha um volume alto de requisições quando removido o filtro, e analisado os logs de forma geral, ele também apresenta um grande volume de requests, **22%**. 

![image](https://github.com/user-attachments/assets/665f058a-9e95-4d64-a51a-6d21264b0dc2)


Outro padrão interessante é o atributo **ClientRequestReferer**, analisando o volume de requisições, um unico referer é responsável por 83.5% das requisições
Esse atribuito normalmente serve para indicar a "origem da navegação", ou página anterior que levou o client a acessar o recurso atual.

![image](https://github.com/user-attachments/assets/71ddc84b-3d23-4449-a3e0-4ccaa9a31e61)

Depdendendo do cenário, pode se tratar até mesmo de um ataque de CSRF.

Com a ajuda do cabeçalho **ClientRequestHost** conseguimos ter uma ideia das aplicações que estão sendo atacas, notamos que o maior volume é direcionado para a porter.biz. Indicando provavelmente que possui algum vetor significativo ou até mesmo uma superficie de ataque maior.

![image](https://github.com/user-attachments/assets/31d105a7-c23e-4254-861c-026fd708e88a)


Outro padrão interessante é que o ataque é executado em horário comercial, iniciando as requisições com mais intensidade pela manhã, aproximadamente, e, evoluindo durante o decorrer do dia. Após as 18h as requisições caem significativamente. E iniciam o ciclo no outro dia.

![image](https://github.com/user-attachments/assets/114fe846-51cb-4994-a314-1ae16a54bbbe)


<h1>3. Identificação de Riscos e Desenvolvimento de Políticas</h1>

<h2>3.1. Identificação de Riscos </h2>

Após analisar a massa de dados, foi possível identificar alguns comportamentos atípicos, indicando tentativas de exploração e ataques direcionados para a aplicação.

Os quais podemos destacar com base na analise os seguintes ataques:

--- **Directory Traversal / Path Traversal** ---

--- **XSS (Cross-Site Scripting)** ---

--- **SQL Injection** ---

--- **Remote Code Execution (RCE)** ---


Existe inúmeras tecnologias e ferramentas de mercado para detectar e responder esses tpos de ataques, abaixo vou colocar sugestões de como mitigar cada vetor.


<h2>3.2. Desenvolvimento de Politicas </h2>

Antes de implementar uma politica efetiva, para tentar responder o incidente da forma mais **rapida** possível, montaria uma estratégia com base nos dados analisados, levando em consideração que:

<h3>// regras rápidas mas não tão inteligentes //</h3>

1 - O atributo **ClientRequestReferer**, um unico referer é responsável por 83.5% das requisições. 
Esse atribuito normalmente serve para indicar a "origem da navegação", ou página anterior que levou o client a acessar o recurso atual. Sabendo disso, com base somente nos logs desenvolveria uma regra de bloqueio da origem __http://hernandez.com__. Reforço que essa regra pode causar impactos em trafego legitimo. E precisaria de mais contexto para ter a certeza de que não se trata de uma origem confiavel.

2 - O AS Number **396982**, similar a regra anterior, poderiamos criar uma regra para bloquear o tráfego oriundo desse AS, contudo, essa seria uma regra um pouco mais delicada, pois pode impactar um volume significativo de tráfego. Antes de aplicar também procuraria ter mais contexto _(histórico d+30 talvez)_.

3 - Rate-limit
Também seria interessante implementar algum mecanismo de rate-limit, analisaria se já utilzamos alguma ferramenta que tenha esse recurso como um WAF, e caso positivo realizaria a configuração na mesma. Contudo, vou apresentar abaixo na sessão 5.Implementação uma solução bem simples de ratelimit.

<h3>// Regras com base nos riscos identificados //</h3>

Com base nos riscos identificados poderiamos criar regras especificas para o cenário, como por exemplo:

**Directory Traversal / Path Traversal**

Mitigação: Valide e sanitize as entradas do usuário, removendo caracteres como "../.". Utilize caminhos absolutos e restrinja acessos a diretórios específicos,

**XSS (Cross-Site Scripting)**

Mitigação: Escape todas as saidas que envolvem codigo como (HTML, JavaScript, CSS) para evitar execução de scripts, já existem  bibliotecas de sanitização, como DOMPurify. Valide entradas, permitindo apenas formatos esperados.

Outra recomendação que poderia auxiliar é configurar as politicas de CSP, _Content Security Policy_  para limitar scripts permitidos.

**SQL Injection**

Mitigação: É recomendado duas principais formas para mitigar SQL I, a primeira é validando e tratando as entradas, e outra prática q tem se tornado comum são as consultas parametrizadas (Prepared Statements) para que buscam evitar injeção direta de SQL.

Também é interessante restringir as permissões no banco de dados (ex.: separação de leitura e escrita).

**Remote Code Execution (RCE)**

Mitigação: Sanar as entradas e validar antes de qualquer execução pelo sistema, s possível nunca utilizar funções como eval(), exec() ou os.system() para processar entradas de usuários.


Por fim, recomendaria executar um teste de intrusão nas aplicações, para certificar que não há vetores de ataque, e se houver, detectar de forma proativa antes de explorações.
Além de manter todos os componentes atualizados.


<h1>5. Implementação</h1>

Abaixo desenvolvi um script em python que busca simular uma politica de segurança que mitigaria os ataques q detectamos na analise!
Sei que o script/implementação pode ser MUITO melhor, mas, tentei fazer algo simples e rápido! 

Utilizei o auxilio de IAs para o desenvolvimento, acredito que o uso dessas ferramentas podem potencializar MUITO nossos ganhos e aprendizagem! e também não sou um "grande" desenvolvedor hehehehe :D


Como Funciona o script propost:

O script simula as entradas de um proxy reverso basico, usando Flask:

- Normalização de Caminhos:
Decodifica entradas como %2E%2E%2F para detectar padrões maliciosos,

- Filtro de Padrões Maliciosos:
Verifica a URL contra uma lista de regex para identificar tentativas de XSS, Directory Traversal, RCE, ou SQL Injection (ataques vistos no cenário dos logs)

- Rate Limiting: _(aproveitei para implementar um rate-limit bem basico)_
Monitora o número de requisições por IP e aplica um limite baseado no tempo.

- Possíveis Respostas:
Bloqueia e retorna código 403 Forbidden para tráfego malicioso.
Permite tráfego legítimo e retorna a URL normalizada.

```python

from flask import Flask, request, jsonify
import re

app = Flask(__name__)

# Lista de padrões maliciosos
MALICIOUS_PATTERNS = [
    r"\.\./",  # Directory Traversal
    r"%00|%2E%2E%2F",  # Codificação de caracteres
    r"etc/passwd|boot.ini",  # Arquivos sensíveis
    r"<script>|<iframe>|javascript:",  # XSS
    r"cmd\.exe|shell\.php",  # RCE
    r"' OR|--|;",  # SQL Injection
]

# Função para verificar padrões maliciosos
def is_malicious(path):
    for pattern in MALICIOUS_PATTERNS:
        if re.search(pattern, path, re.IGNORECASE):
            return True
    return False

# Função de normalização
def normalize_path(path):
    return re.sub(r"%[0-9a-fA-F]{2}", lambda x: chr(int(x.group(0)[1:], 16)), path)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST'])
def analyze_request(path):
    # Normalizar o caminho
    normalized_path = normalize_path(path)
    
    # Checar se o caminho é malicioso
    if is_malicious(normalized_path):
        return jsonify({"status": "blocked", "reason": "Malicious pattern detected"}), 403
    
    # Continuar para o destino (simulado)
    return jsonify({"status": "allowed", "path": normalized_path})

# Rate Limiting (Simples)
REQUEST_COUNT = {}
RATE_LIMIT = 10  # Máximo de 10 requisições por minuto
TIME_WINDOW = 60  # Janela de tempo em segundos

@app.before_request
def rate_limit():
    ip = request.remote_addr
    if ip not in REQUEST_COUNT:
        REQUEST_COUNT[ip] = []
    
    # Registrar timestamp da requisição
    now = time.time()
    REQUEST_COUNT[ip].append(now)
    
    # Remover requisições fora da janela de tempo
    REQUEST_COUNT[ip] = [t for t in REQUEST_COUNT[ip] if now - t < TIME_WINDOW]
    
    # Bloquear se ultrapassar o limite
    if len(REQUEST_COUNT[ip]) > RATE_LIMIT:
        return jsonify({"status": "blocked", "reason": "Rate limit exceeded"}), 429

if __name__ == '__main__':
    app.run(debug=True)


```

Entendo que poderiamos melhorar muito a solução que foi implementada, com mais tempo.
Mas algumas sugestões são: carregar os patterns maliciosos a partir de um JSON alimentado com alguma IA, ou até mesmo uma lista integrada com um SIEM ou MISP ou alguma fonte de IOCS. 

``` python
# Carregar padrões de um arquivo JSON
import json

with open("patterns.json", "r") as f:
    attack_patterns = json.load(f)
```

Outra possíbilidade interessante seria utilizar IA mesmo, com um modelo treinado de machine learning para identificar padrões anômalos em logs do ambiente, isso levaria um tempo de pesquisa e estudo para implementar, mas acredito que pode seguir uma linha de raciociono similar:

Exemplo de abordagem:

1 - Coletar logs legítimos e maliciosos.

2 - Treinar um modelo simples como por exemplo a lib _scikit-learn_ para detectar anomalias.

3 - Integrar o modelo à aplicação ou as ferramentas SIEM/SOAR para decisões dinâmicas.

<h1>6. Considerações Finais / Inovações </h1>

Bom, para finalizar, eu gostei do desafio.
Busquei resolver visando um cenário real, com diversas sugestões, algumas para erradicar o incidente de forma mais rapida porém talvez com impactos para tráfegos legitimos e outras formas mais especifica.

Embora acredite que em um cenário real, teriamos um aparato interessante de ferramentas para atuar como WAF, SIEM, SOAR etc, realizei o desafio com os recursos que possuia.

Na implementação da solução busquei ser o mais prático possível, entendedo que, poderia ser melhorada. Também contei com o uso de IA para auxiliar no desenvolvimento do script, sendo a unica parte que optei por utilizar IA no auxilio do desafio, realizei a primeira versão do script e fui melhorando com IA.

Pessoal, agradeço a oportunidade e espero que a analise e solução proposta aqui para resolução atenda os requisitos!

Tks pela oportunidade.
Espero os próximos passos!


---------------------------------


