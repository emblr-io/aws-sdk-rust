// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchAssociateResourcesToCustomLineItemOutput {
    /// <p>A list of <code>AssociateResourceResponseElement</code> for each resource that's been associated to a percentage custom line item successfully.</p>
    pub successfully_associated_resources: ::std::option::Option<::std::vec::Vec<crate::types::AssociateResourceResponseElement>>,
    /// <p>A list of <code>AssociateResourceResponseElement</code> for each resource that failed association to a percentage custom line item.</p>
    pub failed_associated_resources: ::std::option::Option<::std::vec::Vec<crate::types::AssociateResourceResponseElement>>,
    _request_id: Option<String>,
}
impl BatchAssociateResourcesToCustomLineItemOutput {
    /// <p>A list of <code>AssociateResourceResponseElement</code> for each resource that's been associated to a percentage custom line item successfully.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.successfully_associated_resources.is_none()`.
    pub fn successfully_associated_resources(&self) -> &[crate::types::AssociateResourceResponseElement] {
        self.successfully_associated_resources.as_deref().unwrap_or_default()
    }
    /// <p>A list of <code>AssociateResourceResponseElement</code> for each resource that failed association to a percentage custom line item.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.failed_associated_resources.is_none()`.
    pub fn failed_associated_resources(&self) -> &[crate::types::AssociateResourceResponseElement] {
        self.failed_associated_resources.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for BatchAssociateResourcesToCustomLineItemOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl BatchAssociateResourcesToCustomLineItemOutput {
    /// Creates a new builder-style object to manufacture [`BatchAssociateResourcesToCustomLineItemOutput`](crate::operation::batch_associate_resources_to_custom_line_item::BatchAssociateResourcesToCustomLineItemOutput).
    pub fn builder() -> crate::operation::batch_associate_resources_to_custom_line_item::builders::BatchAssociateResourcesToCustomLineItemOutputBuilder
    {
        crate::operation::batch_associate_resources_to_custom_line_item::builders::BatchAssociateResourcesToCustomLineItemOutputBuilder::default()
    }
}

/// A builder for [`BatchAssociateResourcesToCustomLineItemOutput`](crate::operation::batch_associate_resources_to_custom_line_item::BatchAssociateResourcesToCustomLineItemOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchAssociateResourcesToCustomLineItemOutputBuilder {
    pub(crate) successfully_associated_resources: ::std::option::Option<::std::vec::Vec<crate::types::AssociateResourceResponseElement>>,
    pub(crate) failed_associated_resources: ::std::option::Option<::std::vec::Vec<crate::types::AssociateResourceResponseElement>>,
    _request_id: Option<String>,
}
impl BatchAssociateResourcesToCustomLineItemOutputBuilder {
    /// Appends an item to `successfully_associated_resources`.
    ///
    /// To override the contents of this collection use [`set_successfully_associated_resources`](Self::set_successfully_associated_resources).
    ///
    /// <p>A list of <code>AssociateResourceResponseElement</code> for each resource that's been associated to a percentage custom line item successfully.</p>
    pub fn successfully_associated_resources(mut self, input: crate::types::AssociateResourceResponseElement) -> Self {
        let mut v = self.successfully_associated_resources.unwrap_or_default();
        v.push(input);
        self.successfully_associated_resources = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <code>AssociateResourceResponseElement</code> for each resource that's been associated to a percentage custom line item successfully.</p>
    pub fn set_successfully_associated_resources(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::AssociateResourceResponseElement>>,
    ) -> Self {
        self.successfully_associated_resources = input;
        self
    }
    /// <p>A list of <code>AssociateResourceResponseElement</code> for each resource that's been associated to a percentage custom line item successfully.</p>
    pub fn get_successfully_associated_resources(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AssociateResourceResponseElement>> {
        &self.successfully_associated_resources
    }
    /// Appends an item to `failed_associated_resources`.
    ///
    /// To override the contents of this collection use [`set_failed_associated_resources`](Self::set_failed_associated_resources).
    ///
    /// <p>A list of <code>AssociateResourceResponseElement</code> for each resource that failed association to a percentage custom line item.</p>
    pub fn failed_associated_resources(mut self, input: crate::types::AssociateResourceResponseElement) -> Self {
        let mut v = self.failed_associated_resources.unwrap_or_default();
        v.push(input);
        self.failed_associated_resources = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <code>AssociateResourceResponseElement</code> for each resource that failed association to a percentage custom line item.</p>
    pub fn set_failed_associated_resources(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::AssociateResourceResponseElement>>,
    ) -> Self {
        self.failed_associated_resources = input;
        self
    }
    /// <p>A list of <code>AssociateResourceResponseElement</code> for each resource that failed association to a percentage custom line item.</p>
    pub fn get_failed_associated_resources(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AssociateResourceResponseElement>> {
        &self.failed_associated_resources
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`BatchAssociateResourcesToCustomLineItemOutput`](crate::operation::batch_associate_resources_to_custom_line_item::BatchAssociateResourcesToCustomLineItemOutput).
    pub fn build(self) -> crate::operation::batch_associate_resources_to_custom_line_item::BatchAssociateResourcesToCustomLineItemOutput {
        crate::operation::batch_associate_resources_to_custom_line_item::BatchAssociateResourcesToCustomLineItemOutput {
            successfully_associated_resources: self.successfully_associated_resources,
            failed_associated_resources: self.failed_associated_resources,
            _request_id: self._request_id,
        }
    }
}
