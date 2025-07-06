package com.bytebuilder.checker.service;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.stereotype.Service;

@Service
public class AiServiceImplementation implements AiService {
    
    private ChatClient client;
    
    public AiServiceImplementation(ChatClient.Builder builder) {
        client = builder.build();
    }
    
    @Override
    public String chat(String prompt) {
        return client
                .prompt(prompt)
                .call()
                .content();
    }
}
