// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a parameter group.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ClusterParameterGroup {
    /// <p>The name of the cluster parameter group.</p>
    pub parameter_group_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the cluster parameter group family that this cluster parameter group is compatible with.</p>
    pub parameter_group_family: ::std::option::Option<::std::string::String>,
    /// <p>The description of the parameter group.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The list of tags for the cluster parameter group.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl ClusterParameterGroup {
    /// <p>The name of the cluster parameter group.</p>
    pub fn parameter_group_name(&self) -> ::std::option::Option<&str> {
        self.parameter_group_name.as_deref()
    }
    /// <p>The name of the cluster parameter group family that this cluster parameter group is compatible with.</p>
    pub fn parameter_group_family(&self) -> ::std::option::Option<&str> {
        self.parameter_group_family.as_deref()
    }
    /// <p>The description of the parameter group.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The list of tags for the cluster parameter group.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl ClusterParameterGroup {
    /// Creates a new builder-style object to manufacture [`ClusterParameterGroup`](crate::types::ClusterParameterGroup).
    pub fn builder() -> crate::types::builders::ClusterParameterGroupBuilder {
        crate::types::builders::ClusterParameterGroupBuilder::default()
    }
}

/// A builder for [`ClusterParameterGroup`](crate::types::ClusterParameterGroup).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ClusterParameterGroupBuilder {
    pub(crate) parameter_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) parameter_group_family: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl ClusterParameterGroupBuilder {
    /// <p>The name of the cluster parameter group.</p>
    pub fn parameter_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parameter_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the cluster parameter group.</p>
    pub fn set_parameter_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parameter_group_name = input;
        self
    }
    /// <p>The name of the cluster parameter group.</p>
    pub fn get_parameter_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.parameter_group_name
    }
    /// <p>The name of the cluster parameter group family that this cluster parameter group is compatible with.</p>
    pub fn parameter_group_family(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parameter_group_family = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the cluster parameter group family that this cluster parameter group is compatible with.</p>
    pub fn set_parameter_group_family(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parameter_group_family = input;
        self
    }
    /// <p>The name of the cluster parameter group family that this cluster parameter group is compatible with.</p>
    pub fn get_parameter_group_family(&self) -> &::std::option::Option<::std::string::String> {
        &self.parameter_group_family
    }
    /// <p>The description of the parameter group.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the parameter group.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the parameter group.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The list of tags for the cluster parameter group.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of tags for the cluster parameter group.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The list of tags for the cluster parameter group.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`ClusterParameterGroup`](crate::types::ClusterParameterGroup).
    pub fn build(self) -> crate::types::ClusterParameterGroup {
        crate::types::ClusterParameterGroup {
            parameter_group_name: self.parameter_group_name,
            parameter_group_family: self.parameter_group_family,
            description: self.description,
            tags: self.tags,
        }
    }
}
