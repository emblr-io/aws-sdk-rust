// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeResourceCollectionHealthInput {
    /// <p>An Amazon Web Services resource collection type. This type specifies how analyzed Amazon Web Services resources are defined. The two types of Amazon Web Services resource collections supported are Amazon Web Services CloudFormation stacks and Amazon Web Services resources that contain the same Amazon Web Services tag. DevOps Guru can be configured to analyze the Amazon Web Services resources that are defined in the stacks or that are tagged using the same tag <i>key</i>. You can specify up to 500 Amazon Web Services CloudFormation stacks.</p>
    pub resource_collection_type: ::std::option::Option<crate::types::ResourceCollectionType>,
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If this value is null, it retrieves the first page.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeResourceCollectionHealthInput {
    /// <p>An Amazon Web Services resource collection type. This type specifies how analyzed Amazon Web Services resources are defined. The two types of Amazon Web Services resource collections supported are Amazon Web Services CloudFormation stacks and Amazon Web Services resources that contain the same Amazon Web Services tag. DevOps Guru can be configured to analyze the Amazon Web Services resources that are defined in the stacks or that are tagged using the same tag <i>key</i>. You can specify up to 500 Amazon Web Services CloudFormation stacks.</p>
    pub fn resource_collection_type(&self) -> ::std::option::Option<&crate::types::ResourceCollectionType> {
        self.resource_collection_type.as_ref()
    }
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If this value is null, it retrieves the first page.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl DescribeResourceCollectionHealthInput {
    /// Creates a new builder-style object to manufacture [`DescribeResourceCollectionHealthInput`](crate::operation::describe_resource_collection_health::DescribeResourceCollectionHealthInput).
    pub fn builder() -> crate::operation::describe_resource_collection_health::builders::DescribeResourceCollectionHealthInputBuilder {
        crate::operation::describe_resource_collection_health::builders::DescribeResourceCollectionHealthInputBuilder::default()
    }
}

/// A builder for [`DescribeResourceCollectionHealthInput`](crate::operation::describe_resource_collection_health::DescribeResourceCollectionHealthInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeResourceCollectionHealthInputBuilder {
    pub(crate) resource_collection_type: ::std::option::Option<crate::types::ResourceCollectionType>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeResourceCollectionHealthInputBuilder {
    /// <p>An Amazon Web Services resource collection type. This type specifies how analyzed Amazon Web Services resources are defined. The two types of Amazon Web Services resource collections supported are Amazon Web Services CloudFormation stacks and Amazon Web Services resources that contain the same Amazon Web Services tag. DevOps Guru can be configured to analyze the Amazon Web Services resources that are defined in the stacks or that are tagged using the same tag <i>key</i>. You can specify up to 500 Amazon Web Services CloudFormation stacks.</p>
    /// This field is required.
    pub fn resource_collection_type(mut self, input: crate::types::ResourceCollectionType) -> Self {
        self.resource_collection_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>An Amazon Web Services resource collection type. This type specifies how analyzed Amazon Web Services resources are defined. The two types of Amazon Web Services resource collections supported are Amazon Web Services CloudFormation stacks and Amazon Web Services resources that contain the same Amazon Web Services tag. DevOps Guru can be configured to analyze the Amazon Web Services resources that are defined in the stacks or that are tagged using the same tag <i>key</i>. You can specify up to 500 Amazon Web Services CloudFormation stacks.</p>
    pub fn set_resource_collection_type(mut self, input: ::std::option::Option<crate::types::ResourceCollectionType>) -> Self {
        self.resource_collection_type = input;
        self
    }
    /// <p>An Amazon Web Services resource collection type. This type specifies how analyzed Amazon Web Services resources are defined. The two types of Amazon Web Services resource collections supported are Amazon Web Services CloudFormation stacks and Amazon Web Services resources that contain the same Amazon Web Services tag. DevOps Guru can be configured to analyze the Amazon Web Services resources that are defined in the stacks or that are tagged using the same tag <i>key</i>. You can specify up to 500 Amazon Web Services CloudFormation stacks.</p>
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
    /// Consumes the builder and constructs a [`DescribeResourceCollectionHealthInput`](crate::operation::describe_resource_collection_health::DescribeResourceCollectionHealthInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_resource_collection_health::DescribeResourceCollectionHealthInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_resource_collection_health::DescribeResourceCollectionHealthInput {
                resource_collection_type: self.resource_collection_type,
                next_token: self.next_token,
            },
        )
    }
}
