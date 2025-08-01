// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Placeholder documentation for GetEventBridgeRuleTemplateResponse
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetEventBridgeRuleTemplateOutput {
    /// An eventbridge rule template's ARN (Amazon Resource Name)
    pub arn: ::std::option::Option<::std::string::String>,
    /// Placeholder documentation for __timestampIso8601
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// A resource's optional description.
    pub description: ::std::option::Option<::std::string::String>,
    /// Placeholder documentation for __listOfEventBridgeRuleTemplateTarget
    pub event_targets: ::std::option::Option<::std::vec::Vec<crate::types::EventBridgeRuleTemplateTarget>>,
    /// The type of event to match with the rule.
    pub event_type: ::std::option::Option<crate::types::EventBridgeRuleTemplateEventType>,
    /// An eventbridge rule template group's id. AWS provided template groups have ids that start with `aws-`
    pub group_id: ::std::option::Option<::std::string::String>,
    /// An eventbridge rule template's id. AWS provided templates have ids that start with `aws-`
    pub id: ::std::option::Option<::std::string::String>,
    /// Placeholder documentation for __timestampIso8601
    pub modified_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// A resource's name. Names must be unique within the scope of a resource type in a specific region.
    pub name: ::std::option::Option<::std::string::String>,
    /// Represents the tags associated with a resource.
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl GetEventBridgeRuleTemplateOutput {
    /// An eventbridge rule template's ARN (Amazon Resource Name)
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// Placeholder documentation for __timestampIso8601
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// A resource's optional description.
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// Placeholder documentation for __listOfEventBridgeRuleTemplateTarget
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.event_targets.is_none()`.
    pub fn event_targets(&self) -> &[crate::types::EventBridgeRuleTemplateTarget] {
        self.event_targets.as_deref().unwrap_or_default()
    }
    /// The type of event to match with the rule.
    pub fn event_type(&self) -> ::std::option::Option<&crate::types::EventBridgeRuleTemplateEventType> {
        self.event_type.as_ref()
    }
    /// An eventbridge rule template group's id. AWS provided template groups have ids that start with `aws-`
    pub fn group_id(&self) -> ::std::option::Option<&str> {
        self.group_id.as_deref()
    }
    /// An eventbridge rule template's id. AWS provided templates have ids that start with `aws-`
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// Placeholder documentation for __timestampIso8601
    pub fn modified_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.modified_at.as_ref()
    }
    /// A resource's name. Names must be unique within the scope of a resource type in a specific region.
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// Represents the tags associated with a resource.
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetEventBridgeRuleTemplateOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetEventBridgeRuleTemplateOutput {
    /// Creates a new builder-style object to manufacture [`GetEventBridgeRuleTemplateOutput`](crate::operation::get_event_bridge_rule_template::GetEventBridgeRuleTemplateOutput).
    pub fn builder() -> crate::operation::get_event_bridge_rule_template::builders::GetEventBridgeRuleTemplateOutputBuilder {
        crate::operation::get_event_bridge_rule_template::builders::GetEventBridgeRuleTemplateOutputBuilder::default()
    }
}

/// A builder for [`GetEventBridgeRuleTemplateOutput`](crate::operation::get_event_bridge_rule_template::GetEventBridgeRuleTemplateOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetEventBridgeRuleTemplateOutputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) event_targets: ::std::option::Option<::std::vec::Vec<crate::types::EventBridgeRuleTemplateTarget>>,
    pub(crate) event_type: ::std::option::Option<crate::types::EventBridgeRuleTemplateEventType>,
    pub(crate) group_id: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) modified_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl GetEventBridgeRuleTemplateOutputBuilder {
    /// An eventbridge rule template's ARN (Amazon Resource Name)
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// An eventbridge rule template's ARN (Amazon Resource Name)
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// An eventbridge rule template's ARN (Amazon Resource Name)
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// Placeholder documentation for __timestampIso8601
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// Placeholder documentation for __timestampIso8601
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// Placeholder documentation for __timestampIso8601
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// A resource's optional description.
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// A resource's optional description.
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// A resource's optional description.
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `event_targets`.
    ///
    /// To override the contents of this collection use [`set_event_targets`](Self::set_event_targets).
    ///
    /// Placeholder documentation for __listOfEventBridgeRuleTemplateTarget
    pub fn event_targets(mut self, input: crate::types::EventBridgeRuleTemplateTarget) -> Self {
        let mut v = self.event_targets.unwrap_or_default();
        v.push(input);
        self.event_targets = ::std::option::Option::Some(v);
        self
    }
    /// Placeholder documentation for __listOfEventBridgeRuleTemplateTarget
    pub fn set_event_targets(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EventBridgeRuleTemplateTarget>>) -> Self {
        self.event_targets = input;
        self
    }
    /// Placeholder documentation for __listOfEventBridgeRuleTemplateTarget
    pub fn get_event_targets(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EventBridgeRuleTemplateTarget>> {
        &self.event_targets
    }
    /// The type of event to match with the rule.
    pub fn event_type(mut self, input: crate::types::EventBridgeRuleTemplateEventType) -> Self {
        self.event_type = ::std::option::Option::Some(input);
        self
    }
    /// The type of event to match with the rule.
    pub fn set_event_type(mut self, input: ::std::option::Option<crate::types::EventBridgeRuleTemplateEventType>) -> Self {
        self.event_type = input;
        self
    }
    /// The type of event to match with the rule.
    pub fn get_event_type(&self) -> &::std::option::Option<crate::types::EventBridgeRuleTemplateEventType> {
        &self.event_type
    }
    /// An eventbridge rule template group's id. AWS provided template groups have ids that start with `aws-`
    pub fn group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// An eventbridge rule template group's id. AWS provided template groups have ids that start with `aws-`
    pub fn set_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group_id = input;
        self
    }
    /// An eventbridge rule template group's id. AWS provided template groups have ids that start with `aws-`
    pub fn get_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.group_id
    }
    /// An eventbridge rule template's id. AWS provided templates have ids that start with `aws-`
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// An eventbridge rule template's id. AWS provided templates have ids that start with `aws-`
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// An eventbridge rule template's id. AWS provided templates have ids that start with `aws-`
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// Placeholder documentation for __timestampIso8601
    pub fn modified_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.modified_at = ::std::option::Option::Some(input);
        self
    }
    /// Placeholder documentation for __timestampIso8601
    pub fn set_modified_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.modified_at = input;
        self
    }
    /// Placeholder documentation for __timestampIso8601
    pub fn get_modified_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.modified_at
    }
    /// A resource's name. Names must be unique within the scope of a resource type in a specific region.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// A resource's name. Names must be unique within the scope of a resource type in a specific region.
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// A resource's name. Names must be unique within the scope of a resource type in a specific region.
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// Represents the tags associated with a resource.
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// Represents the tags associated with a resource.
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// Represents the tags associated with a resource.
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetEventBridgeRuleTemplateOutput`](crate::operation::get_event_bridge_rule_template::GetEventBridgeRuleTemplateOutput).
    pub fn build(self) -> crate::operation::get_event_bridge_rule_template::GetEventBridgeRuleTemplateOutput {
        crate::operation::get_event_bridge_rule_template::GetEventBridgeRuleTemplateOutput {
            arn: self.arn,
            created_at: self.created_at,
            description: self.description,
            event_targets: self.event_targets,
            event_type: self.event_type,
            group_id: self.group_id,
            id: self.id,
            modified_at: self.modified_at,
            name: self.name,
            tags: self.tags,
            _request_id: self._request_id,
        }
    }
}
