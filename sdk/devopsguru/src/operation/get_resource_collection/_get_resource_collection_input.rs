// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetResourceCollectionInput {
    /// <p>The type of Amazon Web Services resource collections to return. The one valid value is <code>CLOUD_FORMATION</code> for Amazon Web Services CloudFormation stacks.</p>
    pub resource_collection_type: ::std::option::Option<crate::types::ResourceCollectionType>,
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If this value is null, it retrieves the first page.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl GetResourceCollectionInput {
    /// <p>The type of Amazon Web Services resource collections to return. The one valid value is <code>CLOUD_FORMATION</code> for Amazon Web Services CloudFormation stacks.</p>
    pub fn resource_collection_type(&self) -> ::std::option::Option<&crate::types::ResourceCollectionType> {
        self.resource_collection_type.as_ref()
    }
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If this value is null, it retrieves the first page.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl GetResourceCollectionInput {
    /// Creates a new builder-style object to manufacture [`GetResourceCollectionInput`](crate::operation::get_resource_collection::GetResourceCollectionInput).
    pub fn builder() -> crate::operation::get_resource_collection::builders::GetResourceCollectionInputBuilder {
        crate::operation::get_resource_collection::builders::GetResourceCollectionInputBuilder::default()
    }
}

/// A builder for [`GetResourceCollectionInput`](crate::operation::get_resource_collection::GetResourceCollectionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetResourceCollectionInputBuilder {
    pub(crate) resource_collection_type: ::std::option::Option<crate::types::ResourceCollectionType>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl GetResourceCollectionInputBuilder {
    /// <p>The type of Amazon Web Services resource collections to return. The one valid value is <code>CLOUD_FORMATION</code> for Amazon Web Services CloudFormation stacks.</p>
    /// This field is required.
    pub fn resource_collection_type(mut self, input: crate::types::ResourceCollectionType) -> Self {
        self.resource_collection_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of Amazon Web Services resource collections to return. The one valid value is <code>CLOUD_FORMATION</code> for Amazon Web Services CloudFormation stacks.</p>
    pub fn set_resource_collection_type(mut self, input: ::std::option::Option<crate::types::ResourceCollectionType>) -> Self {
        self.resource_collection_type = input;
        self
    }
    /// <p>The type of Amazon Web Services resource collections to return. The one valid value is <code>CLOUD_FORMATION</code> for Amazon Web Services CloudFormation stacks.</p>
    pub fn get_resource_collection_type(&self) -> &::std::option::Option<crate::types::ResourceCollectionType> {
        &self.resource_collection_type
    }
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If this value is null, it retrieves the first page.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If this value is null, it retrieves the first page.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If this value is null, it retrieves the first page.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`GetResourceCollectionInput`](crate::operation::get_resource_collection::GetResourceCollectionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_resource_collection::GetResourceCollectionInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_resource_collection::GetResourceCollectionInput {
            resource_collection_type: self.resource_collection_type,
            next_token: self.next_token,
        })
    }
}
