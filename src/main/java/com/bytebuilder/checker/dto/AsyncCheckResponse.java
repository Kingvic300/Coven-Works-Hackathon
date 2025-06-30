package com.bytebuilder.checker.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Response for asynchronous website check requests")
public class AsyncCheckResponse {
    @Schema(description = "Unique identifier for tracking the asynchronous analysis")
    private String trackingId;

    @Schema(description = "Status message for the asynchronous request")
    private String message;

    @Schema(description = "The URL that was submitted for analysis")
    private String url;
}