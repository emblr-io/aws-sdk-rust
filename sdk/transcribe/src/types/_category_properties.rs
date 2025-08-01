// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides you with the properties of the Call Analytics category you specified in your request. This includes the list of rules that define the specified category.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CategoryProperties {
    /// <p>The name of the Call Analytics category. Category names are case sensitive and must be unique within an Amazon Web Services account.</p>
    pub category_name: ::std::option::Option<::std::string::String>,
    /// <p>The rules used to define a Call Analytics category. Each category can have between 1 and 20 rules.</p>
    pub rules: ::std::option::Option<::std::vec::Vec<crate::types::Rule>>,
    /// <p>The date and time the specified Call Analytics category was created.</p>
    /// <p>Timestamps are in the format <code>YYYY-MM-DD'T'HH:MM:SS.SSSSSS-UTC</code>. For example, <code>2022-05-04T12:32:58.761000-07:00</code> represents 12:32 PM UTC-7 on May 4, 2022.</p>
    pub create_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time the specified Call Analytics category was last updated.</p>
    /// <p>Timestamps are in the format <code>YYYY-MM-DD'T'HH:MM:SS.SSSSSS-UTC</code>. For example, <code>2022-05-05T12:45:32.691000-07:00</code> represents 12:45 PM UTC-7 on May 5, 2022.</p>
    pub last_update_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The tags, each in the form of a key:value pair, assigned to the specified call analytics category.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>The input type associated with the specified category. <code>POST_CALL</code> refers to a category that is applied to batch transcriptions; <code>REAL_TIME</code> refers to a category that is applied to streaming transcriptions.</p>
    pub input_type: ::std::option::Option<crate::types::InputType>,
}
impl CategoryProperties {
    /// <p>The name of the Call Analytics category. Category names are case sensitive and must be unique within an Amazon Web Services account.</p>
    pub fn category_name(&self) -> ::std::option::Option<&str> {
        self.category_name.as_deref()
    }
    /// <p>The rules used to define a Call Analytics category. Each category can have between 1 and 20 rules.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.rules.is_none()`.
    pub fn rules(&self) -> &[crate::types::Rule] {
        self.rules.as_deref().unwrap_or_default()
    }
    /// <p>The date and time the specified Call Analytics category was created.</p>
    /// <p>Timestamps are in the format <code>YYYY-MM-DD'T'HH:MM:SS.SSSSSS-UTC</code>. For example, <code>2022-05-04T12:32:58.761000-07:00</code> represents 12:32 PM UTC-7 on May 4, 2022.</p>
    pub fn create_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.create_time.as_ref()
    }
    /// <p>The date and time the specified Call Analytics category was last updated.</p>
    /// <p>Timestamps are in the format <code>YYYY-MM-DD'T'HH:MM:SS.SSSSSS-UTC</code>. For example, <code>2022-05-05T12:45:32.691000-07:00</code> represents 12:45 PM UTC-7 on May 5, 2022.</p>
    pub fn last_update_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_update_time.as_ref()
    }
    /// <p>The tags, each in the form of a key:value pair, assigned to the specified call analytics category.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>The input type associated with the specified category. <code>POST_CALL</code> refers to a category that is applied to batch transcriptions; <code>REAL_TIME</code> refers to a category that is applied to streaming transcriptions.</p>
    pub fn input_type(&self) -> ::std::option::Option<&crate::types::InputType> {
        self.input_type.as_ref()
    }
}
impl CategoryProperties {
    /// Creates a new builder-style object to manufacture [`CategoryProperties`](crate::types::CategoryProperties).
    pub fn builder() -> crate::types::builders::CategoryPropertiesBuilder {
        crate::types::builders::CategoryPropertiesBuilder::default()
    }
}

/// A builder for [`CategoryProperties`](crate::types::CategoryProperties).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CategoryPropertiesBuilder {
    pub(crate) category_name: ::std::option::Option<::std::string::String>,
    pub(crate) rules: ::std::option::Option<::std::vec::Vec<crate::types::Rule>>,
    pub(crate) create_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_update_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) input_type: ::std::option::Option<crate::types::InputType>,
}
impl CategoryPropertiesBuilder {
    /// <p>The name of the Call Analytics category. Category names are case sensitive and must be unique within an Amazon Web Services account.</p>
    pub fn category_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.category_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Call Analytics category. Category names are case sensitive and must be unique within an Amazon Web Services account.</p>
    pub fn set_category_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.category_name = input;
        self
    }
    /// <p>The name of the Call Analytics category. Category names are case sensitive and must be unique within an Amazon Web Services account.</p>
    pub fn get_category_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.category_name
    }
    /// Appends an item to `rules`.
    ///
    /// To override the contents of this collection use [`set_rules`](Self::set_rules).
    ///
    /// <p>The rules used to define a Call Analytics category. Each category can have between 1 and 20 rules.</p>
    pub fn rules(mut self, input: crate::types::Rule) -> Self {
        let mut v = self.rules.unwrap_or_default();
        v.push(input);
        self.rules = ::std::option::Option::Some(v);
        self
    }
    /// <p>The rules used to define a Call Analytics category. Each category can have between 1 and 20 rules.</p>
    pub fn set_rules(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Rule>>) -> Self {
        self.rules = input;
        self
    }
    /// <p>The rules used to define a Call Analytics category. Each category can have between 1 and 20 rules.</p>
    pub fn get_rules(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Rule>> {
        &self.rules
    }
    /// <p>The date and time the specified Call Analytics category was created.</p>
    /// <p>Timestamps are in the format <code>YYYY-MM-DD'T'HH:MM:SS.SSSSSS-UTC</code>. For example, <code>2022-05-04T12:32:58.761000-07:00</code> represents 12:32 PM UTC-7 on May 4, 2022.</p>
    pub fn create_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.create_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time the specified Call Analytics category was created.</p>
    /// <p>Timestamps are in the format <code>YYYY-MM-DD'T'HH:MM:SS.SSSSSS-UTC</code>. For example, <code>2022-05-04T12:32:58.761000-07:00</code> represents 12:32 PM UTC-7 on May 4, 2022.</p>
    pub fn set_create_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.create_time = input;
        self
    }
    /// <p>The date and time the specified Call Analytics category was created.</p>
    /// <p>Timestamps are in the format <code>YYYY-MM-DD'T'HH:MM:SS.SSSSSS-UTC</code>. For example, <code>2022-05-04T12:32:58.761000-07:00</code> represents 12:32 PM UTC-7 on May 4, 2022.</p>
    pub fn get_create_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.create_time
    }
    /// <p>The date and time the specified Call Analytics category was last updated.</p>
    /// <p>Timestamps are in the format <code>YYYY-MM-DD'T'HH:MM:SS.SSSSSS-UTC</code>. For example, <code>2022-05-05T12:45:32.691000-07:00</code> represents 12:45 PM UTC-7 on May 5, 2022.</p>
    pub fn last_update_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_update_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time the specified Call Analytics category was last updated.</p>
    /// <p>Timestamps are in the format <code>YYYY-MM-DD'T'HH:MM:SS.SSSSSS-UTC</code>. For example, <code>2022-05-05T12:45:32.691000-07:00</code> represents 12:45 PM UTC-7 on May 5, 2022.</p>
    pub fn set_last_update_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_update_time = input;
        self
    }
    /// <p>The date and time the specified Call Analytics category was last updated.</p>
    /// <p>Timestamps are in the format <code>YYYY-MM-DD'T'HH:MM:SS.SSSSSS-UTC</code>. For example, <code>2022-05-05T12:45:32.691000-07:00</code> represents 12:45 PM UTC-7 on May 5, 2022.</p>
    pub fn get_last_update_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_update_time
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags, each in the form of a key:value pair, assigned to the specified call analytics category.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags, each in the form of a key:value pair, assigned to the specified call analytics category.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags, each in the form of a key:value pair, assigned to the specified call analytics category.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>The input type associated with the specified category. <code>POST_CALL</code> refers to a category that is applied to batch transcriptions; <code>REAL_TIME</code> refers to a category that is applied to streaming transcriptions.</p>
    pub fn input_type(mut self, input: crate::types::InputType) -> Self {
        self.input_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The input type associated with the specified category. <code>POST_CALL</code> refers to a category that is applied to batch transcriptions; <code>REAL_TIME</code> refers to a category that is applied to streaming transcriptions.</p>
    pub fn set_input_type(mut self, input: ::std::option::Option<crate::types::InputType>) -> Self {
        self.input_type = input;
        self
    }
    /// <p>The input type associated with the specified category. <code>POST_CALL</code> refers to a category that is applied to batch transcriptions; <code>REAL_TIME</code> refers to a category that is applied to streaming transcriptions.</p>
    pub fn get_input_type(&self) -> &::std::option::Option<crate::types::InputType> {
        &self.input_type
    }
    /// Consumes the builder and constructs a [`CategoryProperties`](crate::types::CategoryProperties).
    pub fn build(self) -> crate::types::CategoryProperties {
        crate::types::CategoryProperties {
            category_name: self.category_name,
            rules: self.rules,
            create_time: self.create_time,
            last_update_time: self.last_update_time,
            tags: self.tags,
            input_type: self.input_type,
        }
    }
}
