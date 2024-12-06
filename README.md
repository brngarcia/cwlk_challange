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


--- **Remote Code Execution (RCE)** ---

/shell.php?cmd=cat%20/etc/passwd 

/../../../windows/system32/cmd.exe

Após realizar executar a triagem e analise inicial, foram identificadas 1.375 requisições maliciosas, a qual montei a seguinte query no Elastic:
> ClientRequestPath : "/\";!--\"<XSS>=&{()}" or "/../../../../../../../../../../etc/shadow" or "/%00%01%02%03%04%05%06%07" or "/../../../../../../../../../../etc/shadow" or "/../../../../windows/system32/cmd.exe" or "/../../../etc/passwd" or "/../../../windows/win.ini" or "/../../boot.ini" or "/.git/config" or "/<iframe src=''javascript:alert(1)'></iframe>" or "/<img src='x'' onerror='alert(1)'>" or "/<marquee><img 'src=1 onerror=alert(1)></marquee>" or  "/<meta http-equiv='refresh' content='0" or "/<script>alert('XSS')</script>" or "/admin.php?user=admin&password=admin" or "/api/v1/users?search=" or "/shell.php?cmd=cat%20/etc/passwd"

Dentro desse volume de requisições **maliciosas**, foi possível identificar alguns itens que poderiamos utilizar para a remediação, como por exemplo, o alto volume de requisições enviadas pelo AS numero **396982** totalizando **37%** do volume total.
![image](https://github.com/user-attachments/assets/5be9b566-7cbb-42b5-bd7d-1ceca6134846)


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


<h1>3.1 Riscos & Ameaças </h1>

<h1>4. Remediações </h1>


<h1>5. Implementações </h1>


<h1>6. Considerações Finais </h1>


---------------------------------

<h2>3.1. Análise de dados</h2>
Analise completamente os dados de tráfego de rede fornecidos. Identifique padrões, anomalias e potenciais riscos de segurança. Documente claramente seu processo de análise e descobertas.

<h2>3.2. Identificação de Riscos e Desenvolvimento de Políticas</h2>
Com base em sua análise e conhecimento, identifique potenciais riscos de segurança e desenvolva uma política de segurança abrangente para mitigar ou prevenir esses riscos. Explique sua lógica por trás da política e como ela aborda os riscos identificados.

<h2>3.3. Implementação</h2>
Implemente uma solução que imponha a política de segurança. Isso pode ser na forma de um script ou programa que simula como a política avaliaria e filtraria o tráfego de rede. Garanta que sua implementação seja adaptável a vários padrões de tráfego.

<h2>3.4. Explicação e Documentação</h2>
Forneça uma explicação clara de sua abordagem, incluindo como você analisou os dados, identificou riscos e desenvolveu a política de segurança. Certifique-se de destacar seu pensamento lógico e soluções inovadoras.

<h2>3.5. Inovação</h2>
Considere adicionar recursos ou melhorias que vão além dos requisitos básicos. Como você pode melhorar a eficácia, eficiência e adaptabilidade da sua política de segurança? Quais outras tecnologias você poderia aplicar? Como você poderia aplicar IA neste caso? Seja criativo e pense fora da caixa!
