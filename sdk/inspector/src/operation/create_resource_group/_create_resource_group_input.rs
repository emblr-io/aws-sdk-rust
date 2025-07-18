// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateResourceGroupInput {
    /// <p>A collection of keys and an array of possible values, '\[{"key":"key1","values":\["Value1","Value2"\]},{"key":"Key2","values":\["Value3"\]}\]'.</p>
    /// <p>For example,'\[{"key":"Name","values":\["TestEC2Instance"\]}\]'.</p>
    pub resource_group_tags: ::std::option::Option<::std::vec::Vec<crate::types::ResourceGroupTag>>,
}
impl CreateResourceGroupInput {
    /// <p>A collection of keys and an array of possible values, '\[{"key":"key1","values":\["Value1","Value2"\]},{"key":"Key2","values":\["Value3"\]}\]'.</p>
    /// <p>For example,'\[{"key":"Name","values":\["TestEC2Instance"\]}\]'.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.resource_group_tags.is_none()`.
    pub fn resource_group_tags(&self) -> &[crate::types::ResourceGroupTag] {
        self.resource_group_tags.as_deref().unwrap_or_default()
    }
}
impl CreateResourceGroupInput {
    /// Creates a new builder-style object to manufacture [`CreateResourceGroupInput`](crate::operation::create_resource_group::CreateResourceGroupInput).
    pub fn builder() -> crate::operation::create_resource_group::builders::CreateResourceGroupInputBuilder {
        crate::operation::create_resource_group::builders::CreateResourceGroupInputBuilder::default()
    }
}

/// A builder for [`CreateResourceGroupInput`](crate::operation::create_resource_group::CreateResourceGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateResourceGroupInputBuilder {
    pub(crate) resource_group_tags: ::std::option::Option<::std::vec::Vec<crate::types::ResourceGroupTag>>,
}
impl CreateResourceGroupInputBuilder {
    /// Appends an item to `resource_group_tags`.
    ///
    /// To override the contents of this collection use [`set_resource_group_tags`](Self::set_resource_group_tags).
    ///
    /// <p>A collection of keys and an array of possible values, '\[{"key":"key1","values":\["Value1","Value2"\]},{"key":"Key2","values":\["Value3"\]}\]'.</p>
    /// <p>For example,'\[{"key":"Name","values":\["TestEC2Instance"\]}\]'.</p>
    pub fn resource_group_tags(mut self, input: crate::types::ResourceGroupTag) -> Self {
        let mut v = self.resource_group_tags.unwrap_or_default();
        v.push(input);
        self.resource_group_tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A collection of keys and an array of possible values, '\[{"key":"key1","values":\["Value1","Value2"\]},{"key":"Key2","values":\["Value3"\]}\]'.</p>
    /// <p>For example,'\[{"key":"Name","values":\["TestEC2Instance"\]}\]'.</p>
    pub fn set_resource_group_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ResourceGroupTag>>) -> Self {
        self.resource_group_tags = input;
        self
    }
    /// <p>A collection of keys and an array of possible values, '\[{"key":"key1","values":\["Value1","Value2"\]},{"key":"Key2","values":\["Value3"\]}\]'.</p>
    /// <p>For example,'\[{"key":"Name","values":\["TestEC2Instance"\]}\]'.</p>
    pub fn get_resource_group_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ResourceGroupTag>> {
        &self.resource_group_tags
    }
    /// Consumes the builder and constructs a [`CreateResourceGroupInput`](crate::operation::create_resource_group::CreateResourceGroupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_resource_group::CreateResourceGroupInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_resource_group::CreateResourceGroupInput {
            resource_group_tags: self.resource_group_tags,
        })
    }
}
