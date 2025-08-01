// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the input of a <code>RemoveTagsFromOnPremisesInstances</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RemoveTagsFromOnPremisesInstancesInput {
    /// <p>The tag key-value pairs to remove from the on-premises instances.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>The names of the on-premises instances from which to remove tags.</p>
    pub instance_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl RemoveTagsFromOnPremisesInstancesInput {
    /// <p>The tag key-value pairs to remove from the on-premises instances.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>The names of the on-premises instances from which to remove tags.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.instance_names.is_none()`.
    pub fn instance_names(&self) -> &[::std::string::String] {
        self.instance_names.as_deref().unwrap_or_default()
    }
}
impl RemoveTagsFromOnPremisesInstancesInput {
    /// Creates a new builder-style object to manufacture [`RemoveTagsFromOnPremisesInstancesInput`](crate::operation::remove_tags_from_on_premises_instances::RemoveTagsFromOnPremisesInstancesInput).
    pub fn builder() -> crate::operation::remove_tags_from_on_premises_instances::builders::RemoveTagsFromOnPremisesInstancesInputBuilder {
        crate::operation::remove_tags_from_on_premises_instances::builders::RemoveTagsFromOnPremisesInstancesInputBuilder::default()
    }
}

/// A builder for [`RemoveTagsFromOnPremisesInstancesInput`](crate::operation::remove_tags_from_on_premises_instances::RemoveTagsFromOnPremisesInstancesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RemoveTagsFromOnPremisesInstancesInputBuilder {
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) instance_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl RemoveTagsFromOnPremisesInstancesInputBuilder {
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tag key-value pairs to remove from the on-premises instances.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tag key-value pairs to remove from the on-premises instances.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tag key-value pairs to remove from the on-premises instances.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Appends an item to `instance_names`.
    ///
    /// To override the contents of this collection use [`set_instance_names`](Self::set_instance_names).
    ///
    /// <p>The names of the on-premises instances from which to remove tags.</p>
    pub fn instance_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.instance_names.unwrap_or_default();
        v.push(input.into());
        self.instance_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>The names of the on-premises instances from which to remove tags.</p>
    pub fn set_instance_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.instance_names = input;
        self
    }
    /// <p>The names of the on-premises instances from which to remove tags.</p>
    pub fn get_instance_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.instance_names
    }
    /// Consumes the builder and constructs a [`RemoveTagsFromOnPremisesInstancesInput`](crate::operation::remove_tags_from_on_premises_instances::RemoveTagsFromOnPremisesInstancesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::remove_tags_from_on_premises_instances::RemoveTagsFromOnPremisesInstancesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::remove_tags_from_on_premises_instances::RemoveTagsFromOnPremisesInstancesInput {
                tags: self.tags,
                instance_names: self.instance_names,
            },
        )
    }
}
