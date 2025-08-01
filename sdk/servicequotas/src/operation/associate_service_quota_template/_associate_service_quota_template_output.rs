// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateServiceQuotaTemplateOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for AssociateServiceQuotaTemplateOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl AssociateServiceQuotaTemplateOutput {
    /// Creates a new builder-style object to manufacture [`AssociateServiceQuotaTemplateOutput`](crate::operation::associate_service_quota_template::AssociateServiceQuotaTemplateOutput).
    pub fn builder() -> crate::operation::associate_service_quota_template::builders::AssociateServiceQuotaTemplateOutputBuilder {
        crate::operation::associate_service_quota_template::builders::AssociateServiceQuotaTemplateOutputBuilder::default()
    }
}

/// A builder for [`AssociateServiceQuotaTemplateOutput`](crate::operation::associate_service_quota_template::AssociateServiceQuotaTemplateOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateServiceQuotaTemplateOutputBuilder {
    _request_id: Option<String>,
}
impl AssociateServiceQuotaTemplateOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`AssociateServiceQuotaTemplateOutput`](crate::operation::associate_service_quota_template::AssociateServiceQuotaTemplateOutput).
    pub fn build(self) -> crate::operation::associate_service_quota_template::AssociateServiceQuotaTemplateOutput {
        crate::operation::associate_service_quota_template::AssociateServiceQuotaTemplateOutput {
            _request_id: self._request_id,
        }
    }
}
