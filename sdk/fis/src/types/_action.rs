// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes an action. For more information, see <a href="https://docs.aws.amazon.com/fis/latest/userguide/fis-actions-reference.html">FIS actions</a> in the <i>Fault Injection Service User Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Action {
    /// <p>The ID of the action.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the action.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The description for the action.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The action parameters, if applicable.</p>
    pub parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::ActionParameter>>,
    /// <p>The supported targets for the action.</p>
    pub targets: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::ActionTarget>>,
    /// <p>The tags for the action.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl Action {
    /// <p>The ID of the action.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the action.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The description for the action.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The action parameters, if applicable.</p>
    pub fn parameters(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::ActionParameter>> {
        self.parameters.as_ref()
    }
    /// <p>The supported targets for the action.</p>
    pub fn targets(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::ActionTarget>> {
        self.targets.as_ref()
    }
    /// <p>The tags for the action.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl Action {
    /// Creates a new builder-style object to manufacture [`Action`](crate::types::Action).
    pub fn builder() -> crate::types::builders::ActionBuilder {
        crate::types::builders::ActionBuilder::default()
    }
}

/// A builder for [`Action`](crate::types::Action).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ActionBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::ActionParameter>>,
    pub(crate) targets: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::ActionTarget>>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl ActionBuilder {
    /// <p>The ID of the action.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the action.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the action.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The Amazon Resource Name (ARN) of the action.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the action.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the action.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The description for the action.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description for the action.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description for the action.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Adds a key-value pair to `parameters`.
    ///
    /// To override the contents of this collection use [`set_parameters`](Self::set_parameters).
    ///
    /// <p>The action parameters, if applicable.</p>
    pub fn parameters(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::ActionParameter) -> Self {
        let mut hash_map = self.parameters.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.parameters = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The action parameters, if applicable.</p>
    pub fn set_parameters(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::ActionParameter>>,
    ) -> Self {
        self.parameters = input;
        self
    }
    /// <p>The action parameters, if applicable.</p>
    pub fn get_parameters(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::ActionParameter>> {
        &self.parameters
    }
    /// Adds a key-value pair to `targets`.
    ///
    /// To override the contents of this collection use [`set_targets`](Self::set_targets).
    ///
    /// <p>The supported targets for the action.</p>
    pub fn targets(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::ActionTarget) -> Self {
        let mut hash_map = self.targets.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.targets = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The supported targets for the action.</p>
    pub fn set_targets(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::ActionTarget>>,
    ) -> Self {
        self.targets = input;
        self
    }
    /// <p>The supported targets for the action.</p>
    pub fn get_targets(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::ActionTarget>> {
        &self.targets
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags for the action.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags for the action.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags for the action.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`Action`](crate::types::Action).
    pub fn build(self) -> crate::types::Action {
        crate::types::Action {
            id: self.id,
            arn: self.arn,
            description: self.description,
            parameters: self.parameters,
            targets: self.targets,
            tags: self.tags,
        }
    }
}
