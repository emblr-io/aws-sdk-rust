// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::fmt::Debug)]
pub struct DetectAnomaliesInput {
    /// <p>The name of the project that contains the model version that you want to use.</p>
    pub project_name: ::std::option::Option<::std::string::String>,
    /// <p>The version of the model that you want to use.</p>
    pub model_version: ::std::option::Option<::std::string::String>,
    /// <p>The unencrypted image bytes that you want to analyze.</p>
    #[cfg_attr(any(feature = "serde-serialize", feature = "serde-deserialize"), serde(skip))]
    pub body: ::aws_smithy_types::byte_stream::ByteStream,
    /// <p>The type of the image passed in <code>Body</code>. Valid values are <code>image/png</code> (PNG format images) and <code>image/jpeg</code> (JPG format images).</p>
    pub content_type: ::std::option::Option<::std::string::String>,
}
impl DetectAnomaliesInput {
    /// <p>The name of the project that contains the model version that you want to use.</p>
    pub fn project_name(&self) -> ::std::option::Option<&str> {
        self.project_name.as_deref()
    }
    /// <p>The version of the model that you want to use.</p>
    pub fn model_version(&self) -> ::std::option::Option<&str> {
        self.model_version.as_deref()
    }
    /// <p>The unencrypted image bytes that you want to analyze.</p>
    pub fn body(&self) -> &::aws_smithy_types::byte_stream::ByteStream {
        &self.body
    }
    /// <p>The type of the image passed in <code>Body</code>. Valid values are <code>image/png</code> (PNG format images) and <code>image/jpeg</code> (JPG format images).</p>
    pub fn content_type(&self) -> ::std::option::Option<&str> {
        self.content_type.as_deref()
    }
}
impl DetectAnomaliesInput {
    /// Creates a new builder-style object to manufacture [`DetectAnomaliesInput`](crate::operation::detect_anomalies::DetectAnomaliesInput).
    pub fn builder() -> crate::operation::detect_anomalies::builders::DetectAnomaliesInputBuilder {
        crate::operation::detect_anomalies::builders::DetectAnomaliesInputBuilder::default()
    }
}

/// A builder for [`DetectAnomaliesInput`](crate::operation::detect_anomalies::DetectAnomaliesInput).
#[derive(::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DetectAnomaliesInputBuilder {
    pub(crate) project_name: ::std::option::Option<::std::string::String>,
    pub(crate) model_version: ::std::option::Option<::std::string::String>,
    pub(crate) body: ::std::option::Option<::aws_smithy_types::byte_stream::ByteStream>,
    pub(crate) content_type: ::std::option::Option<::std::string::String>,
}
impl DetectAnomaliesInputBuilder {
    /// <p>The name of the project that contains the model version that you want to use.</p>
    /// This field is required.
    pub fn project_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.project_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the project that contains the model version that you want to use.</p>
    pub fn set_project_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.project_name = input;
        self
    }
    /// <p>The name of the project that contains the model version that you want to use.</p>
    pub fn get_project_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.project_name
    }
    /// <p>The version of the model that you want to use.</p>
    /// This field is required.
    pub fn model_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the model that you want to use.</p>
    pub fn set_model_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_version = input;
        self
    }
    /// <p>The version of the model that you want to use.</p>
    pub fn get_model_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_version
    }
    /// <p>The unencrypted image bytes that you want to analyze.</p>
    /// This field is required.
    pub fn body(mut self, input: ::aws_smithy_types::byte_stream::ByteStream) -> Self {
        self.body = ::std::option::Option::Some(input);
        self
    }
    /// <p>The unencrypted image bytes that you want to analyze.</p>
    pub fn set_body(mut self, input: ::std::option::Option<::aws_smithy_types::byte_stream::ByteStream>) -> Self {
        self.body = input;
        self
    }
    /// <p>The unencrypted image bytes that you want to analyze.</p>
    pub fn get_body(&self) -> &::std::option::Option<::aws_smithy_types::byte_stream::ByteStream> {
        &self.body
    }
    /// <p>The type of the image passed in <code>Body</code>. Valid values are <code>image/png</code> (PNG format images) and <code>image/jpeg</code> (JPG format images).</p>
    /// This field is required.
    pub fn content_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.content_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of the image passed in <code>Body</code>. Valid values are <code>image/png</code> (PNG format images) and <code>image/jpeg</code> (JPG format images).</p>
    pub fn set_content_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.content_type = input;
        self
    }
    /// <p>The type of the image passed in <code>Body</code>. Valid values are <code>image/png</code> (PNG format images) and <code>image/jpeg</code> (JPG format images).</p>
    pub fn get_content_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.content_type
    }
    /// Consumes the builder and constructs a [`DetectAnomaliesInput`](crate::operation::detect_anomalies::DetectAnomaliesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::detect_anomalies::DetectAnomaliesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::detect_anomalies::DetectAnomaliesInput {
            project_name: self.project_name,
            model_version: self.model_version,
            body: self.body.unwrap_or_default(),
            content_type: self.content_type,
        })
    }
}
