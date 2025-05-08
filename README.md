Trabalho desenvolvido durante a matéria de Segurança Computacional. Abrange troca de chaves assimétricas para a criação de uma chave simétrica de sessão e a aplicação de assinaturas digitais para garantir autenticidade de mensagens. O HSM utilizado para gerar e armazenar chaves foi provido pela Dinamo em parceria com a UTFPR de Toledo.
Para executar o projeto é necessário ter o Maven instalado na sua máquina

Para compilar: mvn clean compile
Para rodar o lado servidor: mvn exec:java -Pservidor
Para rodar o lado cliente: mvn exec:java -Pcliente