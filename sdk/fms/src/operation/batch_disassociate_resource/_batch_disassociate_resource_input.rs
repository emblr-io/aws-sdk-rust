// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchDisassociateResourceInput {
    /// <p>A unique identifier for the resource set, used in a request to refer to the resource set.</p>
    pub resource_set_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The uniform resource identifiers (URI) of resources that should be disassociated from the resource set. The URIs must be Amazon Resource Names (ARNs).</p>
    pub items: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl BatchDisassociateResourceInput {
    /// <p>A unique identifier for the resource set, used in a request to refer to the resource set.</p>
    pub fn resource_set_identifier(&self) -> ::std::option::Option<&str> {
        self.resource_set_identifier.as_deref()
    }
    /// <p>The uniform resource identifiers (URI) of resources that should be disassociated from the resource set. The URIs must be Amazon Resource Names (ARNs).</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.items.is_none()`.
    pub fn items(&self) -> &[::std::string::String] {
        self.items.as_deref().unwrap_or_default()
    }
}
impl BatchDisassociateResourceInput {
    /// Creates a new builder-style object to manufacture [`BatchDisassociateResourceInput`](crate::operation::batch_disassociate_resource::BatchDisassociateResourceInput).
    pub fn builder() -> crate::operation::batch_disassociate_resource::builders::BatchDisassociateResourceInputBuilder {
        crate::operation::batch_disassociate_resource::builders::BatchDisassociateResourceInputBuilder::default()
    }
}

/// A builder for [`BatchDisassociateResourceInput`](crate::operation::batch_disassociate_resource::BatchDisassociateResourceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchDisassociateResourceInputBuilder {
    pub(crate) resource_set_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) items: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl BatchDisassociateResourceInputBuilder {
    /// <p>A unique identifier for the resource set, used in a request to refer to the resource set.</p>
    /// This field is required.
    pub fn resource_set_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_set_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the resource set, used in a request to refer to the resource set.</p>
    pub fn set_resource_set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_set_identifier = input;
        self
    }
    /// <p>A unique identifier for the resource set, used in a request to refer to the resource set.</p>
    pub fn get_resource_set_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_set_identifier
    }
    /// Appends an item to `items`.
    ///
    /// To override the contents of this collection use [`set_items`](Self::set_items).
    ///
    /// <p>The uniform resource identifiers (URI) of resources that should be disassociated from the resource set. The URIs must be Amazon Resource Names (ARNs).</p>
    pub fn items(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.items.unwrap_or_default();
        v.push(input.into());
        self.items = ::std::option::Option::Some(v);
        self
    }
    /// <p>The uniform resource identifiers (URI) of resources that should be disassociated from the resource set. The URIs must be Amazon Resource Names (ARNs).</p>
    pub fn set_items(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.items = input;
        self
    }
    /// <p>The uniform resource identifiers (URI) of resources that should be disassociated from the resource set. The URIs must be Amazon Resource Names (ARNs).</p>
    pub fn get_items(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.items
    }
    /// Consumes the builder and constructs a [`BatchDisassociateResourceInput`](crate::operation::batch_disassociate_resource::BatchDisassociateResourceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::batch_disassociate_resource::BatchDisassociateResourceInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::batch_disassociate_resource::BatchDisassociateResourceInput {
            resource_set_identifier: self.resource_set_identifier,
            items: self.items,
        })
    }
}
