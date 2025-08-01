// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartLendingAnalysisInput {
    /// <p>The Amazon S3 bucket that contains the document to be processed. It's used by asynchronous operations.</p>
    /// <p>The input document can be an image file in JPEG or PNG format. It can also be a file in PDF format.</p>
    pub document_location: ::std::option::Option<crate::types::DocumentLocation>,
    /// <p>The idempotent token that you use to identify the start request. If you use the same token with multiple <code>StartLendingAnalysis</code> requests, the same <code>JobId</code> is returned. Use <code>ClientRequestToken</code> to prevent the same job from being accidentally started more than once. For more information, see <a href="https://docs.aws.amazon.com/textract/latest/dg/api-sync.html">Calling Amazon Textract Asynchronous Operations</a>.</p>
    pub client_request_token: ::std::option::Option<::std::string::String>,
    /// <p>An identifier that you specify to be included in the completion notification published to the Amazon SNS topic. For example, you can use <code>JobTag</code> to identify the type of document that the completion notification corresponds to (such as a tax form or a receipt).</p>
    pub job_tag: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Simple Notification Service (Amazon SNS) topic to which Amazon Textract publishes the completion status of an asynchronous document operation.</p>
    pub notification_channel: ::std::option::Option<crate::types::NotificationChannel>,
    /// <p>Sets whether or not your output will go to a user created bucket. Used to set the name of the bucket, and the prefix on the output file.</p>
    /// <p><code>OutputConfig</code> is an optional parameter which lets you adjust where your output will be placed. By default, Amazon Textract will store the results internally and can only be accessed by the Get API operations. With <code>OutputConfig</code> enabled, you can set the name of the bucket the output will be sent to the file prefix of the results where you can download your results. Additionally, you can set the <code>KMSKeyID</code> parameter to a customer master key (CMK) to encrypt your output. Without this parameter set Amazon Textract will encrypt server-side using the AWS managed CMK for Amazon S3.</p>
    /// <p>Decryption of Customer Content is necessary for processing of the documents by Amazon Textract. If your account is opted out under an AI services opt out policy then all unencrypted Customer Content is immediately and permanently deleted after the Customer Content has been processed by the service. No copy of of the output is retained by Amazon Textract. For information about how to opt out, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_ai-opt-out.html"> Managing AI services opt-out policy. </a></p>
    /// <p>For more information on data privacy, see the <a href="https://aws.amazon.com/compliance/data-privacy-faq/">Data Privacy FAQ</a>.</p>
    pub output_config: ::std::option::Option<crate::types::OutputConfig>,
    /// <p>The KMS key used to encrypt the inference results. This can be in either Key ID or Key Alias format. When a KMS key is provided, the KMS key will be used for server-side encryption of the objects in the customer bucket. When this parameter is not enabled, the result will be encrypted server side, using SSE-S3.</p>
    pub kms_key_id: ::std::option::Option<::std::string::String>,
}
impl StartLendingAnalysisInput {
    /// <p>The Amazon S3 bucket that contains the document to be processed. It's used by asynchronous operations.</p>
    /// <p>The input document can be an image file in JPEG or PNG format. It can also be a file in PDF format.</p>
    pub fn document_location(&self) -> ::std::option::Option<&crate::types::DocumentLocation> {
        self.document_location.as_ref()
    }
    /// <p>The idempotent token that you use to identify the start request. If you use the same token with multiple <code>StartLendingAnalysis</code> requests, the same <code>JobId</code> is returned. Use <code>ClientRequestToken</code> to prevent the same job from being accidentally started more than once. For more information, see <a href="https://docs.aws.amazon.com/textract/latest/dg/api-sync.html">Calling Amazon Textract Asynchronous Operations</a>.</p>
    pub fn client_request_token(&self) -> ::std::option::Option<&str> {
        self.client_request_token.as_deref()
    }
    /// <p>An identifier that you specify to be included in the completion notification published to the Amazon SNS topic. For example, you can use <code>JobTag</code> to identify the type of document that the completion notification corresponds to (such as a tax form or a receipt).</p>
    pub fn job_tag(&self) -> ::std::option::Option<&str> {
        self.job_tag.as_deref()
    }
    /// <p>The Amazon Simple Notification Service (Amazon SNS) topic to which Amazon Textract publishes the completion status of an asynchronous document operation.</p>
    pub fn notification_channel(&self) -> ::std::option::Option<&crate::types::NotificationChannel> {
        self.notification_channel.as_ref()
    }
    /// <p>Sets whether or not your output will go to a user created bucket. Used to set the name of the bucket, and the prefix on the output file.</p>
    /// <p><code>OutputConfig</code> is an optional parameter which lets you adjust where your output will be placed. By default, Amazon Textract will store the results internally and can only be accessed by the Get API operations. With <code>OutputConfig</code> enabled, you can set the name of the bucket the output will be sent to the file prefix of the results where you can download your results. Additionally, you can set the <code>KMSKeyID</code> parameter to a customer master key (CMK) to encrypt your output. Without this parameter set Amazon Textract will encrypt server-side using the AWS managed CMK for Amazon S3.</p>
    /// <p>Decryption of Customer Content is necessary for processing of the documents by Amazon Textract. If your account is opted out under an AI services opt out policy then all unencrypted Customer Content is immediately and permanently deleted after the Customer Content has been processed by the service. No copy of of the output is retained by Amazon Textract. For information about how to opt out, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_ai-opt-out.html"> Managing AI services opt-out policy. </a></p>
    /// <p>For more information on data privacy, see the <a href="https://aws.amazon.com/compliance/data-privacy-faq/">Data Privacy FAQ</a>.</p>
    pub fn output_config(&self) -> ::std::option::Option<&crate::types::OutputConfig> {
        self.output_config.as_ref()
    }
    /// <p>The KMS key used to encrypt the inference results. This can be in either Key ID or Key Alias format. When a KMS key is provided, the KMS key will be used for server-side encryption of the objects in the customer bucket. When this parameter is not enabled, the result will be encrypted server side, using SSE-S3.</p>
    pub fn kms_key_id(&self) -> ::std::option::Option<&str> {
        self.kms_key_id.as_deref()
    }
}
impl StartLendingAnalysisInput {
    /// Creates a new builder-style object to manufacture [`StartLendingAnalysisInput`](crate::operation::start_lending_analysis::StartLendingAnalysisInput).
    pub fn builder() -> crate::operation::start_lending_analysis::builders::StartLendingAnalysisInputBuilder {
        crate::operation::start_lending_analysis::builders::StartLendingAnalysisInputBuilder::default()
    }
}

/// A builder for [`StartLendingAnalysisInput`](crate::operation::start_lending_analysis::StartLendingAnalysisInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartLendingAnalysisInputBuilder {
    pub(crate) document_location: ::std::option::Option<crate::types::DocumentLocation>,
    pub(crate) client_request_token: ::std::option::Option<::std::string::String>,
    pub(crate) job_tag: ::std::option::Option<::std::string::String>,
    pub(crate) notification_channel: ::std::option::Option<crate::types::NotificationChannel>,
    pub(crate) output_config: ::std::option::Option<crate::types::OutputConfig>,
    pub(crate) kms_key_id: ::std::option::Option<::std::string::String>,
}
impl StartLendingAnalysisInputBuilder {
    /// <p>The Amazon S3 bucket that contains the document to be processed. It's used by asynchronous operations.</p>
    /// <p>The input document can be an image file in JPEG or PNG format. It can also be a file in PDF format.</p>
    /// This field is required.
    pub fn document_location(mut self, input: crate::types::DocumentLocation) -> Self {
        self.document_location = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Amazon S3 bucket that contains the document to be processed. It's used by asynchronous operations.</p>
    /// <p>The input document can be an image file in JPEG or PNG format. It can also be a file in PDF format.</p>
    pub fn set_document_location(mut self, input: ::std::option::Option<crate::types::DocumentLocation>) -> Self {
        self.document_location = input;
        self
    }
    /// <p>The Amazon S3 bucket that contains the document to be processed. It's used by asynchronous operations.</p>
    /// <p>The input document can be an image file in JPEG or PNG format. It can also be a file in PDF format.</p>
    pub fn get_document_location(&self) -> &::std::option::Option<crate::types::DocumentLocation> {
        &self.document_location
    }
    /// <p>The idempotent token that you use to identify the start request. If you use the same token with multiple <code>StartLendingAnalysis</code> requests, the same <code>JobId</code> is returned. Use <code>ClientRequestToken</code> to prevent the same job from being accidentally started more than once. For more information, see <a href="https://docs.aws.amazon.com/textract/latest/dg/api-sync.html">Calling Amazon Textract Asynchronous Operations</a>.</p>
    pub fn client_request_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_request_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The idempotent token that you use to identify the start request. If you use the same token with multiple <code>StartLendingAnalysis</code> requests, the same <code>JobId</code> is returned. Use <code>ClientRequestToken</code> to prevent the same job from being accidentally started more than once. For more information, see <a href="https://docs.aws.amazon.com/textract/latest/dg/api-sync.html">Calling Amazon Textract Asynchronous Operations</a>.</p>
    pub fn set_client_request_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_request_token = input;
        self
    }
    /// <p>The idempotent token that you use to identify the start request. If you use the same token with multiple <code>StartLendingAnalysis</code> requests, the same <code>JobId</code> is returned. Use <code>ClientRequestToken</code> to prevent the same job from being accidentally started more than once. For more information, see <a href="https://docs.aws.amazon.com/textract/latest/dg/api-sync.html">Calling Amazon Textract Asynchronous Operations</a>.</p>
    pub fn get_client_request_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_request_token
    }
    /// <p>An identifier that you specify to be included in the completion notification published to the Amazon SNS topic. For example, you can use <code>JobTag</code> to identify the type of document that the completion notification corresponds to (such as a tax form or a receipt).</p>
    pub fn job_tag(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_tag = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An identifier that you specify to be included in the completion notification published to the Amazon SNS topic. For example, you can use <code>JobTag</code> to identify the type of document that the completion notification corresponds to (such as a tax form or a receipt).</p>
    pub fn set_job_tag(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_tag = input;
        self
    }
    /// <p>An identifier that you specify to be included in the completion notification published to the Amazon SNS topic. For example, you can use <code>JobTag</code> to identify the type of document that the completion notification corresponds to (such as a tax form or a receipt).</p>
    pub fn get_job_tag(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_tag
    }
    /// <p>The Amazon Simple Notification Service (Amazon SNS) topic to which Amazon Textract publishes the completion status of an asynchronous document operation.</p>
    pub fn notification_channel(mut self, input: crate::types::NotificationChannel) -> Self {
        self.notification_channel = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Amazon Simple Notification Service (Amazon SNS) topic to which Amazon Textract publishes the completion status of an asynchronous document operation.</p>
    pub fn set_notification_channel(mut self, input: ::std::option::Option<crate::types::NotificationChannel>) -> Self {
        self.notification_channel = input;
        self
    }
    /// <p>The Amazon Simple Notification Service (Amazon SNS) topic to which Amazon Textract publishes the completion status of an asynchronous document operation.</p>
    pub fn get_notification_channel(&self) -> &::std::option::Option<crate::types::NotificationChannel> {
        &self.notification_channel
    }
    /// <p>Sets whether or not your output will go to a user created bucket. Used to set the name of the bucket, and the prefix on the output file.</p>
    /// <p><code>OutputConfig</code> is an optional parameter which lets you adjust where your output will be placed. By default, Amazon Textract will store the results internally and can only be accessed by the Get API operations. With <code>OutputConfig</code> enabled, you can set the name of the bucket the output will be sent to the file prefix of the results where you can download your results. Additionally, you can set the <code>KMSKeyID</code> parameter to a customer master key (CMK) to encrypt your output. Without this parameter set Amazon Textract will encrypt server-side using the AWS managed CMK for Amazon S3.</p>
    /// <p>Decryption of Customer Content is necessary for processing of the documents by Amazon Textract. If your account is opted out under an AI services opt out policy then all unencrypted Customer Content is immediately and permanently deleted after the Customer Content has been processed by the service. No copy of of the output is retained by Amazon Textract. For information about how to opt out, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_ai-opt-out.html"> Managing AI services opt-out policy. </a></p>
    /// <p>For more information on data privacy, see the <a href="https://aws.amazon.com/compliance/data-privacy-faq/">Data Privacy FAQ</a>.</p>
    pub fn output_config(mut self, input: crate::types::OutputConfig) -> Self {
        self.output_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Sets whether or not your output will go to a user created bucket. Used to set the name of the bucket, and the prefix on the output file.</p>
    /// <p><code>OutputConfig</code> is an optional parameter which lets you adjust where your output will be placed. By default, Amazon Textract will store the results internally and can only be accessed by the Get API operations. With <code>OutputConfig</code> enabled, you can set the name of the bucket the output will be sent to the file prefix of the results where you can download your results. Additionally, you can set the <code>KMSKeyID</code> parameter to a customer master key (CMK) to encrypt your output. Without this parameter set Amazon Textract will encrypt server-side using the AWS managed CMK for Amazon S3.</p>
    /// <p>Decryption of Customer Content is necessary for processing of the documents by Amazon Textract. If your account is opted out under an AI services opt out policy then all unencrypted Customer Content is immediately and permanently deleted after the Customer Content has been processed by the service. No copy of of the output is retained by Amazon Textract. For information about how to opt out, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_ai-opt-out.html"> Managing AI services opt-out policy. </a></p>
    /// <p>For more information on data privacy, see the <a href="https://aws.amazon.com/compliance/data-privacy-faq/">Data Privacy FAQ</a>.</p>
    pub fn set_output_config(mut self, input: ::std::option::Option<crate::types::OutputConfig>) -> Self {
        self.output_config = input;
        self
    }
    /// <p>Sets whether or not your output will go to a user created bucket. Used to set the name of the bucket, and the prefix on the output file.</p>
    /// <p><code>OutputConfig</code> is an optional parameter which lets you adjust where your output will be placed. By default, Amazon Textract will store the results internally and can only be accessed by the Get API operations. With <code>OutputConfig</code> enabled, you can set the name of the bucket the output will be sent to the file prefix of the results where you can download your results. Additionally, you can set the <code>KMSKeyID</code> parameter to a customer master key (CMK) to encrypt your output. Without this parameter set Amazon Textract will encrypt server-side using the AWS managed CMK for Amazon S3.</p>
    /// <p>Decryption of Customer Content is necessary for processing of the documents by Amazon Textract. If your account is opted out under an AI services opt out policy then all unencrypted Customer Content is immediately and permanently deleted after the Customer Content has been processed by the service. No copy of of the output is retained by Amazon Textract. For information about how to opt out, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_ai-opt-out.html"> Managing AI services opt-out policy. </a></p>
    /// <p>For more information on data privacy, see the <a href="https://aws.amazon.com/compliance/data-privacy-faq/">Data Privacy FAQ</a>.</p>
    pub fn get_output_config(&self) -> &::std::option::Option<crate::types::OutputConfig> {
        &self.output_config
    }
    /// <p>The KMS key used to encrypt the inference results. This can be in either Key ID or Key Alias format. When a KMS key is provided, the KMS key will be used for server-side encryption of the objects in the customer bucket. When this parameter is not enabled, the result will be encrypted server side, using SSE-S3.</p>
    pub fn kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The KMS key used to encrypt the inference results. This can be in either Key ID or Key Alias format. When a KMS key is provided, the KMS key will be used for server-side encryption of the objects in the customer bucket. When this parameter is not enabled, the result will be encrypted server side, using SSE-S3.</p>
    pub fn set_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_id = input;
        self
    }
    /// <p>The KMS key used to encrypt the inference results. This can be in either Key ID or Key Alias format. When a KMS key is provided, the KMS key will be used for server-side encryption of the objects in the customer bucket. When this parameter is not enabled, the result will be encrypted server side, using SSE-S3.</p>
    pub fn get_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_id
    }
    /// Consumes the builder and constructs a [`StartLendingAnalysisInput`](crate::operation::start_lending_analysis::StartLendingAnalysisInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::start_lending_analysis::StartLendingAnalysisInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::start_lending_analysis::StartLendingAnalysisInput {
            document_location: self.document_location,
            client_request_token: self.client_request_token,
            job_tag: self.job_tag,
            notification_channel: self.notification_channel,
            output_config: self.output_config,
            kms_key_id: self.kms_key_id,
        })
    }
}
