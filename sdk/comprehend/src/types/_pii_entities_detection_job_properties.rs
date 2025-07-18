// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides information about a PII entities detection job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PiiEntitiesDetectionJobProperties {
    /// <p>The identifier assigned to the PII entities detection job.</p>
    pub job_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the PII entities detection job. It is a unique, fully qualified identifier for the job. It includes the Amazon Web Services account, Amazon Web Services Region, and the job ID. The format of the ARN is as follows:</p>
    /// <p><code>arn:<partition>
    /// :comprehend:
    /// <region>
    /// :
    /// <account-id>
    /// :pii-entities-detection-job/
    /// <job-id></job-id>
    /// </account-id>
    /// </region>
    /// </partition></code></p>
    /// <p>The following is an example job ARN:</p>
    /// <p><code>arn:aws:comprehend:us-west-2:111122223333:pii-entities-detection-job/1234abcd12ab34cd56ef1234567890ab</code></p>
    pub job_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name that you assigned the PII entities detection job.</p>
    pub job_name: ::std::option::Option<::std::string::String>,
    /// <p>The current status of the PII entities detection job. If the status is <code>FAILED</code>, the <code>Message</code> field shows the reason for the failure.</p>
    pub job_status: ::std::option::Option<crate::types::JobStatus>,
    /// <p>A description of the status of a job.</p>
    pub message: ::std::option::Option<::std::string::String>,
    /// <p>The time that the PII entities detection job was submitted for processing.</p>
    pub submit_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The time that the PII entities detection job completed.</p>
    pub end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The input properties for a PII entities detection job.</p>
    pub input_data_config: ::std::option::Option<crate::types::InputDataConfig>,
    /// <p>The output data configuration that you supplied when you created the PII entities detection job.</p>
    pub output_data_config: ::std::option::Option<crate::types::PiiOutputDataConfig>,
    /// <p>Provides configuration parameters for PII entity redaction.</p>
    /// <p>This parameter is required if you set the <code>Mode</code> parameter to <code>ONLY_REDACTION</code>. In that case, you must provide a <code>RedactionConfig</code> definition that includes the <code>PiiEntityTypes</code> parameter.</p>
    pub redaction_config: ::std::option::Option<crate::types::RedactionConfig>,
    /// <p>The language code of the input documents.</p>
    pub language_code: ::std::option::Option<crate::types::LanguageCode>,
    /// <p>The Amazon Resource Name (ARN) of the IAM role that grants Amazon Comprehend read access to your input data.</p>
    pub data_access_role_arn: ::std::option::Option<::std::string::String>,
    /// <p>Specifies whether the output provides the locations (offsets) of PII entities or a file in which PII entities are redacted.</p>
    pub mode: ::std::option::Option<crate::types::PiiEntitiesDetectionMode>,
}
impl PiiEntitiesDetectionJobProperties {
    /// <p>The identifier assigned to the PII entities detection job.</p>
    pub fn job_id(&self) -> ::std::option::Option<&str> {
        self.job_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the PII entities detection job. It is a unique, fully qualified identifier for the job. It includes the Amazon Web Services account, Amazon Web Services Region, and the job ID. The format of the ARN is as follows:</p>
    /// <p><code>arn:<partition>
    /// :comprehend:
    /// <region>
    /// :
    /// <account-id>
    /// :pii-entities-detection-job/
    /// <job-id></job-id>
    /// </account-id>
    /// </region>
    /// </partition></code></p>
    /// <p>The following is an example job ARN:</p>
    /// <p><code>arn:aws:comprehend:us-west-2:111122223333:pii-entities-detection-job/1234abcd12ab34cd56ef1234567890ab</code></p>
    pub fn job_arn(&self) -> ::std::option::Option<&str> {
        self.job_arn.as_deref()
    }
    /// <p>The name that you assigned the PII entities detection job.</p>
    pub fn job_name(&self) -> ::std::option::Option<&str> {
        self.job_name.as_deref()
    }
    /// <p>The current status of the PII entities detection job. If the status is <code>FAILED</code>, the <code>Message</code> field shows the reason for the failure.</p>
    pub fn job_status(&self) -> ::std::option::Option<&crate::types::JobStatus> {
        self.job_status.as_ref()
    }
    /// <p>A description of the status of a job.</p>
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
    /// <p>The time that the PII entities detection job was submitted for processing.</p>
    pub fn submit_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.submit_time.as_ref()
    }
    /// <p>The time that the PII entities detection job completed.</p>
    pub fn end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_time.as_ref()
    }
    /// <p>The input properties for a PII entities detection job.</p>
    pub fn input_data_config(&self) -> ::std::option::Option<&crate::types::InputDataConfig> {
        self.input_data_config.as_ref()
    }
    /// <p>The output data configuration that you supplied when you created the PII entities detection job.</p>
    pub fn output_data_config(&self) -> ::std::option::Option<&crate::types::PiiOutputDataConfig> {
        self.output_data_config.as_ref()
    }
    /// <p>Provides configuration parameters for PII entity redaction.</p>
    /// <p>This parameter is required if you set the <code>Mode</code> parameter to <code>ONLY_REDACTION</code>. In that case, you must provide a <code>RedactionConfig</code> definition that includes the <code>PiiEntityTypes</code> parameter.</p>
    pub fn redaction_config(&self) -> ::std::option::Option<&crate::types::RedactionConfig> {
        self.redaction_config.as_ref()
    }
    /// <p>The language code of the input documents.</p>
    pub fn language_code(&self) -> ::std::option::Option<&crate::types::LanguageCode> {
        self.language_code.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role that grants Amazon Comprehend read access to your input data.</p>
    pub fn data_access_role_arn(&self) -> ::std::option::Option<&str> {
        self.data_access_role_arn.as_deref()
    }
    /// <p>Specifies whether the output provides the locations (offsets) of PII entities or a file in which PII entities are redacted.</p>
    pub fn mode(&self) -> ::std::option::Option<&crate::types::PiiEntitiesDetectionMode> {
        self.mode.as_ref()
    }
}
impl PiiEntitiesDetectionJobProperties {
    /// Creates a new builder-style object to manufacture [`PiiEntitiesDetectionJobProperties`](crate::types::PiiEntitiesDetectionJobProperties).
    pub fn builder() -> crate::types::builders::PiiEntitiesDetectionJobPropertiesBuilder {
        crate::types::builders::PiiEntitiesDetectionJobPropertiesBuilder::default()
    }
}

/// A builder for [`PiiEntitiesDetectionJobProperties`](crate::types::PiiEntitiesDetectionJobProperties).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PiiEntitiesDetectionJobPropertiesBuilder {
    pub(crate) job_id: ::std::option::Option<::std::string::String>,
    pub(crate) job_arn: ::std::option::Option<::std::string::String>,
    pub(crate) job_name: ::std::option::Option<::std::string::String>,
    pub(crate) job_status: ::std::option::Option<crate::types::JobStatus>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
    pub(crate) submit_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) input_data_config: ::std::option::Option<crate::types::InputDataConfig>,
    pub(crate) output_data_config: ::std::option::Option<crate::types::PiiOutputDataConfig>,
    pub(crate) redaction_config: ::std::option::Option<crate::types::RedactionConfig>,
    pub(crate) language_code: ::std::option::Option<crate::types::LanguageCode>,
    pub(crate) data_access_role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) mode: ::std::option::Option<crate::types::PiiEntitiesDetectionMode>,
}
impl PiiEntitiesDetectionJobPropertiesBuilder {
    /// <p>The identifier assigned to the PII entities detection job.</p>
    pub fn job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier assigned to the PII entities detection job.</p>
    pub fn set_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_id = input;
        self
    }
    /// <p>The identifier assigned to the PII entities detection job.</p>
    pub fn get_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_id
    }
    /// <p>The Amazon Resource Name (ARN) of the PII entities detection job. It is a unique, fully qualified identifier for the job. It includes the Amazon Web Services account, Amazon Web Services Region, and the job ID. The format of the ARN is as follows:</p>
    /// <p><code>arn:<partition>
    /// :comprehend:
    /// <region>
    /// :
    /// <account-id>
    /// :pii-entities-detection-job/
    /// <job-id></job-id>
    /// </account-id>
    /// </region>
    /// </partition></code></p>
    /// <p>The following is an example job ARN:</p>
    /// <p><code>arn:aws:comprehend:us-west-2:111122223333:pii-entities-detection-job/1234abcd12ab34cd56ef1234567890ab</code></p>
    pub fn job_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the PII entities detection job. It is a unique, fully qualified identifier for the job. It includes the Amazon Web Services account, Amazon Web Services Region, and the job ID. The format of the ARN is as follows:</p>
    /// <p><code>arn:<partition>
    /// :comprehend:
    /// <region>
    /// :
    /// <account-id>
    /// :pii-entities-detection-job/
    /// <job-id></job-id>
    /// </account-id>
    /// </region>
    /// </partition></code></p>
    /// <p>The following is an example job ARN:</p>
    /// <p><code>arn:aws:comprehend:us-west-2:111122223333:pii-entities-detection-job/1234abcd12ab34cd56ef1234567890ab</code></p>
    pub fn set_job_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the PII entities detection job. It is a unique, fully qualified identifier for the job. It includes the Amazon Web Services account, Amazon Web Services Region, and the job ID. The format of the ARN is as follows:</p>
    /// <p><code>arn:<partition>
    /// :comprehend:
    /// <region>
    /// :
    /// <account-id>
    /// :pii-entities-detection-job/
    /// <job-id></job-id>
    /// </account-id>
    /// </region>
    /// </partition></code></p>
    /// <p>The following is an example job ARN:</p>
    /// <p><code>arn:aws:comprehend:us-west-2:111122223333:pii-entities-detection-job/1234abcd12ab34cd56ef1234567890ab</code></p>
    pub fn get_job_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_arn
    }
    /// <p>The name that you assigned the PII entities detection job.</p>
    pub fn job_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name that you assigned the PII entities detection job.</p>
    pub fn set_job_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_name = input;
        self
    }
    /// <p>The name that you assigned the PII entities detection job.</p>
    pub fn get_job_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_name
    }
    /// <p>The current status of the PII entities detection job. If the status is <code>FAILED</code>, the <code>Message</code> field shows the reason for the failure.</p>
    pub fn job_status(mut self, input: crate::types::JobStatus) -> Self {
        self.job_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of the PII entities detection job. If the status is <code>FAILED</code>, the <code>Message</code> field shows the reason for the failure.</p>
    pub fn set_job_status(mut self, input: ::std::option::Option<crate::types::JobStatus>) -> Self {
        self.job_status = input;
        self
    }
    /// <p>The current status of the PII entities detection job. If the status is <code>FAILED</code>, the <code>Message</code> field shows the reason for the failure.</p>
    pub fn get_job_status(&self) -> &::std::option::Option<crate::types::JobStatus> {
        &self.job_status
    }
    /// <p>A description of the status of a job.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the status of a job.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>A description of the status of a job.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// <p>The time that the PII entities detection job was submitted for processing.</p>
    pub fn submit_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.submit_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that the PII entities detection job was submitted for processing.</p>
    pub fn set_submit_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.submit_time = input;
        self
    }
    /// <p>The time that the PII entities detection job was submitted for processing.</p>
    pub fn get_submit_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.submit_time
    }
    /// <p>The time that the PII entities detection job completed.</p>
    pub fn end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that the PII entities detection job completed.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>The time that the PII entities detection job completed.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_time
    }
    /// <p>The input properties for a PII entities detection job.</p>
    pub fn input_data_config(mut self, input: crate::types::InputDataConfig) -> Self {
        self.input_data_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The input properties for a PII entities detection job.</p>
    pub fn set_input_data_config(mut self, input: ::std::option::Option<crate::types::InputDataConfig>) -> Self {
        self.input_data_config = input;
        self
    }
    /// <p>The input properties for a PII entities detection job.</p>
    pub fn get_input_data_config(&self) -> &::std::option::Option<crate::types::InputDataConfig> {
        &self.input_data_config
    }
    /// <p>The output data configuration that you supplied when you created the PII entities detection job.</p>
    pub fn output_data_config(mut self, input: crate::types::PiiOutputDataConfig) -> Self {
        self.output_data_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The output data configuration that you supplied when you created the PII entities detection job.</p>
    pub fn set_output_data_config(mut self, input: ::std::option::Option<crate::types::PiiOutputDataConfig>) -> Self {
        self.output_data_config = input;
        self
    }
    /// <p>The output data configuration that you supplied when you created the PII entities detection job.</p>
    pub fn get_output_data_config(&self) -> &::std::option::Option<crate::types::PiiOutputDataConfig> {
        &self.output_data_config
    }
    /// <p>Provides configuration parameters for PII entity redaction.</p>
    /// <p>This parameter is required if you set the <code>Mode</code> parameter to <code>ONLY_REDACTION</code>. In that case, you must provide a <code>RedactionConfig</code> definition that includes the <code>PiiEntityTypes</code> parameter.</p>
    pub fn redaction_config(mut self, input: crate::types::RedactionConfig) -> Self {
        self.redaction_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides configuration parameters for PII entity redaction.</p>
    /// <p>This parameter is required if you set the <code>Mode</code> parameter to <code>ONLY_REDACTION</code>. In that case, you must provide a <code>RedactionConfig</code> definition that includes the <code>PiiEntityTypes</code> parameter.</p>
    pub fn set_redaction_config(mut self, input: ::std::option::Option<crate::types::RedactionConfig>) -> Self {
        self.redaction_config = input;
        self
    }
    /// <p>Provides configuration parameters for PII entity redaction.</p>
    /// <p>This parameter is required if you set the <code>Mode</code> parameter to <code>ONLY_REDACTION</code>. In that case, you must provide a <code>RedactionConfig</code> definition that includes the <code>PiiEntityTypes</code> parameter.</p>
    pub fn get_redaction_config(&self) -> &::std::option::Option<crate::types::RedactionConfig> {
        &self.redaction_config
    }
    /// <p>The language code of the input documents.</p>
    pub fn language_code(mut self, input: crate::types::LanguageCode) -> Self {
        self.language_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The language code of the input documents.</p>
    pub fn set_language_code(mut self, input: ::std::option::Option<crate::types::LanguageCode>) -> Self {
        self.language_code = input;
        self
    }
    /// <p>The language code of the input documents.</p>
    pub fn get_language_code(&self) -> &::std::option::Option<crate::types::LanguageCode> {
        &self.language_code
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role that grants Amazon Comprehend read access to your input data.</p>
    pub fn data_access_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_access_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role that grants Amazon Comprehend read access to your input data.</p>
    pub fn set_data_access_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_access_role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role that grants Amazon Comprehend read access to your input data.</p>
    pub fn get_data_access_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_access_role_arn
    }
    /// <p>Specifies whether the output provides the locations (offsets) of PII entities or a file in which PII entities are redacted.</p>
    pub fn mode(mut self, input: crate::types::PiiEntitiesDetectionMode) -> Self {
        self.mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the output provides the locations (offsets) of PII entities or a file in which PII entities are redacted.</p>
    pub fn set_mode(mut self, input: ::std::option::Option<crate::types::PiiEntitiesDetectionMode>) -> Self {
        self.mode = input;
        self
    }
    /// <p>Specifies whether the output provides the locations (offsets) of PII entities or a file in which PII entities are redacted.</p>
    pub fn get_mode(&self) -> &::std::option::Option<crate::types::PiiEntitiesDetectionMode> {
        &self.mode
    }
    /// Consumes the builder and constructs a [`PiiEntitiesDetectionJobProperties`](crate::types::PiiEntitiesDetectionJobProperties).
    pub fn build(self) -> crate::types::PiiEntitiesDetectionJobProperties {
        crate::types::PiiEntitiesDetectionJobProperties {
            job_id: self.job_id,
            job_arn: self.job_arn,
            job_name: self.job_name,
            job_status: self.job_status,
            message: self.message,
            submit_time: self.submit_time,
            end_time: self.end_time,
            input_data_config: self.input_data_config,
            output_data_config: self.output_data_config,
            redaction_config: self.redaction_config,
            language_code: self.language_code,
            data_access_role_arn: self.data_access_role_arn,
            mode: self.mode,
        }
    }
}
