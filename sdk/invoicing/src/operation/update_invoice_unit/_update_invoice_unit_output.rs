// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateInvoiceUnitOutput {
    /// <p>The ARN to identify an invoice unit. This information can't be modified or deleted.</p>
    pub invoice_unit_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl UpdateInvoiceUnitOutput {
    /// <p>The ARN to identify an invoice unit. This information can't be modified or deleted.</p>
    pub fn invoice_unit_arn(&self) -> ::std::option::Option<&str> {
        self.invoice_unit_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateInvoiceUnitOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateInvoiceUnitOutput {
    /// Creates a new builder-style object to manufacture [`UpdateInvoiceUnitOutput`](crate::operation::update_invoice_unit::UpdateInvoiceUnitOutput).
    pub fn builder() -> crate::operation::update_invoice_unit::builders::UpdateInvoiceUnitOutputBuilder {
        crate::operation::update_invoice_unit::builders::UpdateInvoiceUnitOutputBuilder::default()
    }
}

/// A builder for [`UpdateInvoiceUnitOutput`](crate::operation::update_invoice_unit::UpdateInvoiceUnitOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateInvoiceUnitOutputBuilder {
    pub(crate) invoice_unit_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl UpdateInvoiceUnitOutputBuilder {
    /// <p>The ARN to identify an invoice unit. This information can't be modified or deleted.</p>
    pub fn invoice_unit_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.invoice_unit_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN to identify an invoice unit. This information can't be modified or deleted.</p>
    pub fn set_invoice_unit_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.invoice_unit_arn = input;
        self
    }
    /// <p>The ARN to identify an invoice unit. This information can't be modified or deleted.</p>
    pub fn get_invoice_unit_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.invoice_unit_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateInvoiceUnitOutput`](crate::operation::update_invoice_unit::UpdateInvoiceUnitOutput).
    pub fn build(self) -> crate::operation::update_invoice_unit::UpdateInvoiceUnitOutput {
        crate::operation::update_invoice_unit::UpdateInvoiceUnitOutput {
            invoice_unit_arn: self.invoice_unit_arn,
            _request_id: self._request_id,
        }
    }
}
