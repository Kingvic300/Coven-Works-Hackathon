package com.bytebuilder.checker.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Request for bulk email spam detection")
public class BulkEmailSpamCheckRequest {

    @NotEmpty(message = "Email list cannot be empty")
    @Size(max = 100, message = "Maximum 100 emails can be checked at once")
    @Valid
    @Schema(description = "List of emails to check for spam", maxLength = 100)
    private List<EmailSpamCheckRequest> emails;
} 