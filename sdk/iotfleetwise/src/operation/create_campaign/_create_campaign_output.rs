// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateCampaignOutput {
    /// <p>The name of the created campaign.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the created campaign.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateCampaignOutput {
    /// <p>The name of the created campaign.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The ARN of the created campaign.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateCampaignOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateCampaignOutput {
    /// Creates a new builder-style object to manufacture [`CreateCampaignOutput`](crate::operation::create_campaign::CreateCampaignOutput).
    pub fn builder() -> crate::operation::create_campaign::builders::CreateCampaignOutputBuilder {
        crate::operation::create_campaign::builders::CreateCampaignOutputBuilder::default()
    }
}

/// A builder for [`CreateCampaignOutput`](crate::operation::create_campaign::CreateCampaignOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateCampaignOutputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateCampaignOutputBuilder {
    /// <p>The name of the created campaign.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the created campaign.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the created campaign.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The ARN of the created campaign.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the created campaign.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The ARN of the created campaign.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateCampaignOutput`](crate::operation::create_campaign::CreateCampaignOutput).
    pub fn build(self) -> crate::operation::create_campaign::CreateCampaignOutput {
        crate::operation::create_campaign::CreateCampaignOutput {
            name: self.name,
            arn: self.arn,
            _request_id: self._request_id,
        }
    }
}
