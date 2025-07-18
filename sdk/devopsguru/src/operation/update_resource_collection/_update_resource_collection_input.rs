// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateResourceCollectionInput {
    /// <p>Specifies if the resource collection in the request is added or deleted to the resource collection.</p>
    pub action: ::std::option::Option<crate::types::UpdateResourceCollectionAction>,
    /// <p>Contains information used to update a collection of Amazon Web Services resources.</p>
    pub resource_collection: ::std::option::Option<crate::types::UpdateResourceCollectionFilter>,
}
impl UpdateResourceCollectionInput {
    /// <p>Specifies if the resource collection in the request is added or deleted to the resource collection.</p>
    pub fn action(&self) -> ::std::option::Option<&crate::types::UpdateResourceCollectionAction> {
        self.action.as_ref()
    }
    /// <p>Contains information used to update a collection of Amazon Web Services resources.</p>
    pub fn resource_collection(&self) -> ::std::option::Option<&crate::types::UpdateResourceCollectionFilter> {
        self.resource_collection.as_ref()
    }
}
impl UpdateResourceCollectionInput {
    /// Creates a new builder-style object to manufacture [`UpdateResourceCollectionInput`](crate::operation::update_resource_collection::UpdateResourceCollectionInput).
    pub fn builder() -> crate::operation::update_resource_collection::builders::UpdateResourceCollectionInputBuilder {
        crate::operation::update_resource_collection::builders::UpdateResourceCollectionInputBuilder::default()
    }
}

/// A builder for [`UpdateResourceCollectionInput`](crate::operation::update_resource_collection::UpdateResourceCollectionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateResourceCollectionInputBuilder {
    pub(crate) action: ::std::option::Option<crate::types::UpdateResourceCollectionAction>,
    pub(crate) resource_collection: ::std::option::Option<crate::types::UpdateResourceCollectionFilter>,
}
impl UpdateResourceCollectionInputBuilder {
    /// <p>Specifies if the resource collection in the request is added or deleted to the resource collection.</p>
    /// This field is required.
    pub fn action(mut self, input: crate::types::UpdateResourceCollectionAction) -> Self {
        self.action = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies if the resource collection in the request is added or deleted to the resource collection.</p>
    pub fn set_action(mut self, input: ::std::option::Option<crate::types::UpdateResourceCollectionAction>) -> Self {
        self.action = input;
        self
    }
    /// <p>Specifies if the resource collection in the request is added or deleted to the resource collection.</p>
    pub fn get_action(&self) -> &::std::option::Option<crate::types::UpdateResourceCollectionAction> {
        &self.action
    }
    /// <p>Contains information used to update a collection of Amazon Web Services resources.</p>
    /// This field is required.
    pub fn resource_collection(mut self, input: crate::types::UpdateResourceCollectionFilter) -> Self {
        self.resource_collection = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains information used to update a collection of Amazon Web Services resources.</p>
    pub fn set_resource_collection(mut self, input: ::std::option::Option<crate::types::UpdateResourceCollectionFilter>) -> Self {
        self.resource_collection = input;
        self
    }
    /// <p>Contains information used to update a collection of Amazon Web Services resources.</p>
    pub fn get_resource_collection(&self) -> &::std::option::Option<crate::types::UpdateResourceCollectionFilter> {
        &self.resource_collection
    }
    /// Consumes the builder and constructs a [`UpdateResourceCollectionInput`](crate::operation::update_resource_collection::UpdateResourceCollectionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_resource_collection::UpdateResourceCollectionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_resource_collection::UpdateResourceCollectionInput {
            action: self.action,
            resource_collection: self.resource_collection,
        })
    }
}
