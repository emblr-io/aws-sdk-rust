// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeLineageGroupInput {
    /// <p>The name of the lineage group.</p>
    pub lineage_group_name: ::std::option::Option<::std::string::String>,
}
impl DescribeLineageGroupInput {
    /// <p>The name of the lineage group.</p>
    pub fn lineage_group_name(&self) -> ::std::option::Option<&str> {
        self.lineage_group_name.as_deref()
    }
}
impl DescribeLineageGroupInput {
    /// Creates a new builder-style object to manufacture [`DescribeLineageGroupInput`](crate::operation::describe_lineage_group::DescribeLineageGroupInput).
    pub fn builder() -> crate::operation::describe_lineage_group::builders::DescribeLineageGroupInputBuilder {
        crate::operation::describe_lineage_group::builders::DescribeLineageGroupInputBuilder::default()
    }
}

/// A builder for [`DescribeLineageGroupInput`](crate::operation::describe_lineage_group::DescribeLineageGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeLineageGroupInputBuilder {
    pub(crate) lineage_group_name: ::std::option::Option<::std::string::String>,
}
impl DescribeLineageGroupInputBuilder {
    /// <p>The name of the lineage group.</p>
    /// This field is required.
    pub fn lineage_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.lineage_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the lineage group.</p>
    pub fn set_lineage_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.lineage_group_name = input;
        self
    }
    /// <p>The name of the lineage group.</p>
    pub fn get_lineage_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.lineage_group_name
    }
    /// Consumes the builder and constructs a [`DescribeLineageGroupInput`](crate::operation::describe_lineage_group::DescribeLineageGroupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_lineage_group::DescribeLineageGroupInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::describe_lineage_group::DescribeLineageGroupInput {
            lineage_group_name: self.lineage_group_name,
        })
    }
}
