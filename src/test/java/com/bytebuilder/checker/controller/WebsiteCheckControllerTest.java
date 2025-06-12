//package com.bytebuilder.checker.controller;
//
//import com.bytebuilder.checker.dto.WebsiteCheckRequest;
//import com.bytebuilder.checker.dto.WebsiteCheckResponse;
//import com.bytebuilder.checker.service.WebsiteCheckService;
//import com.fasterxml.jackson.databind.ObjectMapper;
//import org.junit.jupiter.api.Test;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
//import org.springframework.boot.test.mock.mockito.MockBean;
//import org.springframework.http.MediaType;
//import org.springframework.test.web.servlet.MockMvc;
//
//import static org.mockito.ArgumentMatchers.anyString;
//import static org.mockito.Mockito.when;
//import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
//import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
//
//@WebMvcTest(WebsiteCheckController.class)
//class WebsiteCheckControllerTest {
//
//    @Autowired
//    private MockMvc mockMvc;
//
//    @MockBean
//    private WebsiteCheckService websiteCheckService;
//
//    @Autowired
//    private ObjectMapper objectMapper;
//
//    @Test
//    void testCheckWebsite_ValidUrlSafeAndSecure_ReturnsOk() throws Exception {
//        // Arrange
//        String testUrl = "https://example.com";
//        WebsiteCheckRequest request = new WebsiteCheckRequest();
//        request.setUrl(testUrl);
//
//        when(websiteCheckService.isSecure(testUrl)).thenReturn(true);
//        when(websiteCheckService.isSafeFromScams(testUrl)).thenReturn(true);
//
//        // Act & Assert
//        mockMvc.perform(post("/api/check-website")
//                        .contentType(MediaType.APPLICATION_JSON)
//                        .content(objectMapper.writeValueAsString(request)))
//                .andExpect(status().isOk())
//                .andExpect(jsonPath("$.url").value(testUrl))
//                .andExpect(jsonPath("$.secure").value(true))
//                .andExpect(jsonPath("$.safe").value(true))
//                .andExpect(jsonPath("$.message").value("Website is likely safe"));
//    }