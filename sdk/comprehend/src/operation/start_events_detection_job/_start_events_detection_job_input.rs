// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartEventsDetectionJobInput {
    /// <p>Specifies the format and location of the input data for the job.</p>
    pub input_data_config: ::std::option::Option<crate::types::InputDataConfig>,
    /// <p>Specifies where to send the output files.</p>
    pub output_data_config: ::std::option::Option<crate::types::OutputDataConfig>,
    /// <p>The Amazon Resource Name (ARN) of the IAM role that grants Amazon Comprehend read access to your input data.</p>
    pub data_access_role_arn: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the events detection job.</p>
    pub job_name: ::std::option::Option<::std::string::String>,
    /// <p>The language code of the input documents.</p>
    pub language_code: ::std::option::Option<crate::types::LanguageCode>,
    /// <p>An unique identifier for the request. If you don't set the client request token, Amazon Comprehend generates one.</p>
    pub client_request_token: ::std::option::Option<::std::string::String>,
    /// <p>The types of events to detect in the input documents.</p>
    pub target_event_types: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Tags to associate with the events detection job. A tag is a key-value pair that adds metadata to a resource used by Amazon Comprehend. For example, a tag with "Sales" as the key might be added to a resource to indicate its use by the sales department.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl StartEventsDetectionJobInput {
    /// <p>Specifies the format and location of the input data for the job.</p>
    pub fn input_data_config(&self) -> ::std::option::Option<&crate::types::InputDataConfig> {
        self.input_data_config.as_ref()
    }
    /// <p>Specifies where to send the output files.</p>
    pub fn output_data_config(&self) -> ::std::option::Option<&crate::types::OutputDataConfig> {
        self.output_data_config.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role that grants Amazon Comprehend read access to your input data.</p>
    pub fn data_access_role_arn(&self) -> ::std::option::Option<&str> {
        self.data_access_role_arn.as_deref()
    }
    /// <p>The identifier of the events detection job.</p>
    pub fn job_name(&self) -> ::std::option::Option<&str> {
        self.job_name.as_deref()
    }
    /// <p>The language code of the input documents.</p>
    pub fn language_code(&self) -> ::std::option::Option<&crate::types::LanguageCode> {
        self.language_code.as_ref()
    }
    /// <p>An unique identifier for the request. If you don't set the client request token, Amazon Comprehend generates one.</p>
    pub fn client_request_token(&self) -> ::std::option::Option<&str> {
        self.client_request_token.as_deref()
    }
    /// <p>The types of events to detect in the input documents.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.target_event_types.is_none()`.
    pub fn target_event_types(&self) -> &[::std::string::String] {
        self.target_event_types.as_deref().unwrap_or_default()
    }
    /// <p>Tags to associate with the events detection job. A tag is a key-value pair that adds metadata to a resource used by Amazon Comprehend. For example, a tag with "Sales" as the key might be added to a resource to indicate its use by the sales department.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl StartEventsDetectionJobInput {
    /// Creates a new builder-style object to manufacture [`StartEventsDetectionJobInput`](crate::operation::start_events_detection_job::StartEventsDetectionJobInput).
    pub fn builder() -> crate::operation::start_events_detection_job::builders::StartEventsDetectionJobInputBuilder {
        crate::operation::start_events_detection_job::builders::StartEventsDetectionJobInputBuilder::default()
    }
}

/// A builder for [`StartEventsDetectionJobInput`](crate::operation::start_events_detection_job::StartEventsDetectionJobInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartEventsDetectionJobInputBuilder {
    pub(crate) input_data_config: ::std::option::Option<crate::types::InputDataConfig>,
    pub(crate) output_data_config: ::std::option::Option<crate::types::OutputDataConfig>,
    pub(crate) data_access_role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) job_name: ::std::option::Option<::std::string::String>,
    pub(crate) language_code: ::std::option::Option<crate::types::LanguageCode>,
    pub(crate) client_request_token: ::std::option::Option<::std::string::String>,
    pub(crate) target_event_types: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl StartEventsDetectionJobInputBuilder {
    /// <p>Specifies the format and location of the input data for the job.</p>
    /// This field is required.
    pub fn input_data_config(mut self, input: crate::types::InputDataConfig) -> Self {
        self.input_data_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the format and location of the input data for the job.</p>
    pub fn set_input_data_config(mut self, input: ::std::option::Option<crate::types::InputDataConfig>) -> Self {
        self.input_data_config = input;
        self
    }
    /// <p>Specifies the format and location of the input data for the job.</p>
    pub fn get_input_data_config(&self) -> &::std::option::Option<crate::types::InputDataConfig> {
        &self.input_data_config
    }
    /// <p>Specifies where to send the output files.</p>
    /// This field is required.
    pub fn output_data_config(mut self, input: crate::types::OutputDataConfig) -> Self {
        self.output_data_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies where to send the output files.</p>
    pub fn set_output_data_config(mut self, input: ::std::option::Option<crate::types::OutputDataConfig>) -> Self {
        self.output_data_config = input;
        self
    }
    /// <p>Specifies where to send the output files.</p>
    pub fn get_output_data_config(&self) -> &::std::option::Option<crate::types::OutputDataConfig> {
        &self.output_data_config
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role that grants Amazon Comprehend read access to your input data.</p>
    /// This field is required.
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
    /// <p>The identifier of the events detection job.</p>
    pub fn job_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the events detection job.</p>
    pub fn set_job_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_name = input;
        self
    }
    /// <p>The identifier of the events detection job.</p>
    pub fn get_job_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_name
    }
    /// <p>The language code of the input documents.</p>
    /// This field is required.
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
    /// <p>An unique identifier for the request. If you don't set the client request token, Amazon Comprehend generates one.</p>
    pub fn client_request_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_request_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An unique identifier for the request. If you don't set the client request token, Amazon Comprehend generates one.</p>
    pub fn set_client_request_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_request_token = input;
        self
    }
    /// <p>An unique identifier for the request. If you don't set the client request token, Amazon Comprehend generates one.</p>
    pub fn get_client_request_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_request_token
    }
    /// Appends an item to `target_event_types`.
    ///
    /// To override the contents of this collection use [`set_target_event_types`](Self::set_target_event_types).
    ///
    /// <p>The types of events to detect in the input documents.</p>
    pub fn target_event_types(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.target_event_types.unwrap_or_default();
        v.push(input.into());
        self.target_event_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>The types of events to detect in the input documents.</p>
    pub fn set_target_event_types(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.target_event_types = input;
        self
    }
    /// <p>The types of events to detect in the input documents.</p>
    pub fn get_target_event_types(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.target_event_types
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Tags to associate with the events detection job. A tag is a key-value pair that adds metadata to a resource used by Amazon Comprehend. For example, a tag with "Sales" as the key might be added to a resource to indicate its use by the sales department.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>Tags to associate with the events detection job. A tag is a key-value pair that adds metadata to a resource used by Amazon Comprehend. For example, a tag with "Sales" as the key might be added to a resource to indicate its use by the sales department.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Tags to associate with the events detection job. A tag is a key-value pair that adds metadata to a resource used by Amazon Comprehend. For example, a tag with "Sales" as the key might be added to a resource to indicate its use by the sales department.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`StartEventsDetectionJobInput`](crate::operation::start_events_detection_job::StartEventsDetectionJobInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::start_events_detection_job::StartEventsDetectionJobInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::start_events_detection_job::StartEventsDetectionJobInput {
            input_data_config: self.input_data_config,
            output_data_config: self.output_data_config,
            data_access_role_arn: self.data_access_role_arn,
            job_name: self.job_name,
            language_code: self.language_code,
            client_request_token: self.client_request_token,
            target_event_types: self.target_event_types,
            tags: self.tags,
        })
    }
}
