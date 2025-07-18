// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Thing group metadata.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ThingGroupMetadata {
    /// <p>The parent thing group name.</p>
    pub parent_group_name: ::std::option::Option<::std::string::String>,
    /// <p>The root parent thing group.</p>
    pub root_to_parent_thing_groups: ::std::option::Option<::std::vec::Vec<crate::types::GroupNameAndArn>>,
    /// <p>The UNIX timestamp of when the thing group was created.</p>
    pub creation_date: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ThingGroupMetadata {
    /// <p>The parent thing group name.</p>
    pub fn parent_group_name(&self) -> ::std::option::Option<&str> {
        self.parent_group_name.as_deref()
    }
    /// <p>The root parent thing group.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.root_to_parent_thing_groups.is_none()`.
    pub fn root_to_parent_thing_groups(&self) -> &[crate::types::GroupNameAndArn] {
        self.root_to_parent_thing_groups.as_deref().unwrap_or_default()
    }
    /// <p>The UNIX timestamp of when the thing group was created.</p>
    pub fn creation_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_date.as_ref()
    }
}
impl ThingGroupMetadata {
    /// Creates a new builder-style object to manufacture [`ThingGroupMetadata`](crate::types::ThingGroupMetadata).
    pub fn builder() -> crate::types::builders::ThingGroupMetadataBuilder {
        crate::types::builders::ThingGroupMetadataBuilder::default()
    }
}

/// A builder for [`ThingGroupMetadata`](crate::types::ThingGroupMetadata).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ThingGroupMetadataBuilder {
    pub(crate) parent_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) root_to_parent_thing_groups: ::std::option::Option<::std::vec::Vec<crate::types::GroupNameAndArn>>,
    pub(crate) creation_date: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ThingGroupMetadataBuilder {
    /// <p>The parent thing group name.</p>
    pub fn parent_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parent_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The parent thing group name.</p>
    pub fn set_parent_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parent_group_name = input;
        self
    }
    /// <p>The parent thing group name.</p>
    pub fn get_parent_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.parent_group_name
    }
    /// Appends an item to `root_to_parent_thing_groups`.
    ///
    /// To override the contents of this collection use [`set_root_to_parent_thing_groups`](Self::set_root_to_parent_thing_groups).
    ///
    /// <p>The root parent thing group.</p>
    pub fn root_to_parent_thing_groups(mut self, input: crate::types::GroupNameAndArn) -> Self {
        let mut v = self.root_to_parent_thing_groups.unwrap_or_default();
        v.push(input);
        self.root_to_parent_thing_groups = ::std::option::Option::Some(v);
        self
    }
    /// <p>The root parent thing group.</p>
    pub fn set_root_to_parent_thing_groups(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::GroupNameAndArn>>) -> Self {
        self.root_to_parent_thing_groups = input;
        self
    }
    /// <p>The root parent thing group.</p>
    pub fn get_root_to_parent_thing_groups(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::GroupNameAndArn>> {
        &self.root_to_parent_thing_groups
    }
    /// <p>The UNIX timestamp of when the thing group was created.</p>
    pub fn creation_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The UNIX timestamp of when the thing group was created.</p>
    pub fn set_creation_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_date = input;
        self
    }
    /// <p>The UNIX timestamp of when the thing group was created.</p>
    pub fn get_creation_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_date
    }
    /// Consumes the builder and constructs a [`ThingGroupMetadata`](crate::types::ThingGroupMetadata).
    pub fn build(self) -> crate::types::ThingGroupMetadata {
        crate::types::ThingGroupMetadata {
            parent_group_name: self.parent_group_name,
            root_to_parent_thing_groups: self.root_to_parent_thing_groups,
            creation_date: self.creation_date,
        }
    }
}
