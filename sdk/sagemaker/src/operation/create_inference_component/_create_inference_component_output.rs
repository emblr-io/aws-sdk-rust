// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateInferenceComponentOutput {
    /// <p>The Amazon Resource Name (ARN) of the inference component.</p>
    pub inference_component_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateInferenceComponentOutput {
    /// <p>The Amazon Resource Name (ARN) of the inference component.</p>
    pub fn inference_component_arn(&self) -> ::std::option::Option<&str> {
        self.inference_component_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateInferenceComponentOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateInferenceComponentOutput {
    /// Creates a new builder-style object to manufacture [`CreateInferenceComponentOutput`](crate::operation::create_inference_component::CreateInferenceComponentOutput).
    pub fn builder() -> crate::operation::create_inference_component::builders::CreateInferenceComponentOutputBuilder {
        crate::operation::create_inference_component::builders::CreateInferenceComponentOutputBuilder::default()
    }
}

/// A builder for [`CreateInferenceComponentOutput`](crate::operation::create_inference_component::CreateInferenceComponentOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateInferenceComponentOutputBuilder {
    pub(crate) inference_component_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateInferenceComponentOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the inference component.</p>
    /// This field is required.
    pub fn inference_component_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inference_component_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the inference component.</p>
    pub fn set_inference_component_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inference_component_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the inference component.</p>
    pub fn get_inference_component_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.inference_component_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateInferenceComponentOutput`](crate::operation::create_inference_component::CreateInferenceComponentOutput).
    pub fn build(self) -> crate::operation::create_inference_component::CreateInferenceComponentOutput {
        crate::operation::create_inference_component::CreateInferenceComponentOutput {
            inference_component_arn: self.inference_component_arn,
            _request_id: self._request_id,
        }
    }
}
