## AJUDA CONTRA RANSOMWARE COM FSRM (File System Resource Manager)
Script criado a partir de vários exemplos encontrados, modificados e organizados nesta versão final.
Braier Alves e Jonas Moura - Maio de 2020.

## Atenção! Isto não deve ser tratado como um sistema de segurança.

Backups são a única salvação em um desastre, seja em uma pequena empresa ou em um sistema gigante. Uma rotina de backup precisa ser bem planejada, administrada, testada e mantida em local seguro. Sendo assim, seguem alguns pontos que julgo serem importantes:

- Atenção na configuração dos jobs de backups. Provavelmente esta perda se deu por haver, em algum servidor atacado, alguma indicação para onde os backups estavam indo;
- Lembrem de NUNCA deixar esse caminho disponível. Não façam mapeamento de diretório de storage;
- Evitem acessar interface web de storage sem navegação privada;
- NUNCA deixem salvas credenciais destes equipamentos.

  
  
  
## Como funciona

Ransomwares encriptam arquivos com uma determinada extensão, impossivel de serem decriptados sem a chave específica. Então podemos criar triggers a partir da análise de um conjunto extensões pré informadas.

- Bloqueio de usuário atacado e seus compartilhamentos de rede; 
- Alerta por email;


1. Criar um diretório "c:\dados\scripts" (para aumentar a segurança mantenha o diretório oculto);
2. Download do script https://github.com/braieralves/ransomware-fsrm/blob/master/ransomware-fsrm.ps1 dentro do diretório criado acima e preencha os dados para envio de alerta por email.
3. Executar o script no PowerShell com privilegios de administrador: > PowerShell.exe -c c:\dados\scripts\ransomware-fsrm.ps1

  *Homologado para as versões 2008, 2008R2, 2012, 2012R2, 2016 e 2019 do Windows Server.*

  O script irá verificar se a role FSRM está instalada. Caso contrário ele fará a instalação.
Em seguida fará a criação de um File Group na console do FSRM que demos o nome de "BlockerGroup". Nesse File Group inserimos as extensões que queremos analisar.

  A biblioteca de extensões usadas nesse script foi retirada do seguinte site: https://fsrm.experiant.ca/api/v1/combined (Caso alguém conheça uma biblioteca maior/mais atual pode compartilhar, por favor?).
  
  Podem ser inseridas, manualmente, outras extensões.
  
  
 ##  ProtectList.txt ##

O conteúdo desse arquivo são as pastas que você deseja proteger (inserir uma por linha). 
Se este arquivo existir, apenas as pastas listadas nele serão protegidas. 
Se o arquivo estiver vazio ou tiver apenas entradas inválidas, não haverá pastas protegidas.


##  IncludeList.txt  ##

Aqui você pode inserir, manualmente, extensões que podem não estar listadas no link https://fsrm.experiant.ca/api/v1/combined (essas extensões podem ser enviadas ao site, para serem adicionadas ao conjunto. Ajuda a manter o mais atualizado possível).


## Comando para desbloquear todas os compartilhamentos:

Get-SmbShare -Special $false | ForEach-Object { Unblock-SmbShareAccess -Name $_.Name -AccountName 'UserName' -Force }

