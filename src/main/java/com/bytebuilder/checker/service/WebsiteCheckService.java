package com.bytebuilder.checker.service;

import com.bytebuilder.checker.dto.response.WebsiteAnalysisResult;

public interface WebsiteCheckService {
    WebsiteAnalysisResult analyzeWebsite(String url);
}
