// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeletePartnerAppOutput {
    /// <p>The ARN of the SageMaker Partner AI App that was deleted.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeletePartnerAppOutput {
    /// <p>The ARN of the SageMaker Partner AI App that was deleted.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DeletePartnerAppOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeletePartnerAppOutput {
    /// Creates a new builder-style object to manufacture [`DeletePartnerAppOutput`](crate::operation::delete_partner_app::DeletePartnerAppOutput).
    pub fn builder() -> crate::operation::delete_partner_app::builders::DeletePartnerAppOutputBuilder {
        crate::operation::delete_partner_app::builders::DeletePartnerAppOutputBuilder::default()
    }
}

/// A builder for [`DeletePartnerAppOutput`](crate::operation::delete_partner_app::DeletePartnerAppOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeletePartnerAppOutputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeletePartnerAppOutputBuilder {
    /// <p>The ARN of the SageMaker Partner AI App that was deleted.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the SageMaker Partner AI App that was deleted.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The ARN of the SageMaker Partner AI App that was deleted.</p>
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
    /// Consumes the builder and constructs a [`DeletePartnerAppOutput`](crate::operation::delete_partner_app::DeletePartnerAppOutput).
    pub fn build(self) -> crate::operation::delete_partner_app::DeletePartnerAppOutput {
        crate::operation::delete_partner_app::DeletePartnerAppOutput {
            arn: self.arn,
            _request_id: self._request_id,
        }
    }
}
