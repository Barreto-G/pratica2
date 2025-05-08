package common;

import java.io.IOException;
import java.util.Map;
import java.io.File;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JsonReader {
    public static Map<String, String> ReadJson(String JsonPath){
        ObjectMapper mapper = new ObjectMapper();
        
        try {
            return mapper.readValue(
                new File(JsonPath),
                new TypeReference<Map<String, String>>() {}
            );
        } catch (IOException e) {
            System.out.println("Não foi possível ler o arquivo JSON, verifique o nome ou caminho do arquivo");
            e.printStackTrace();
            return null;
        }
    }
}
