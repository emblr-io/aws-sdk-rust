// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that contains an <code>Engagement</code>'s subset of fields.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct EngagementSummary {
    /// <p>The Amazon Resource Name (ARN) of the created Engagement.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier for the Engagement.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The title of the Engagement.</p>
    pub title: ::std::option::Option<::std::string::String>,
    /// <p>The date and time when the Engagement was created.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The AWS Account ID of the Engagement creator.</p>
    pub created_by: ::std::option::Option<::std::string::String>,
    /// <p>The number of members in the Engagement.</p>
    pub member_count: ::std::option::Option<i32>,
}
impl EngagementSummary {
    /// <p>The Amazon Resource Name (ARN) of the created Engagement.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The unique identifier for the Engagement.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The title of the Engagement.</p>
    pub fn title(&self) -> ::std::option::Option<&str> {
        self.title.as_deref()
    }
    /// <p>The date and time when the Engagement was created.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>The AWS Account ID of the Engagement creator.</p>
    pub fn created_by(&self) -> ::std::option::Option<&str> {
        self.created_by.as_deref()
    }
    /// <p>The number of members in the Engagement.</p>
    pub fn member_count(&self) -> ::std::option::Option<i32> {
        self.member_count
    }
}
impl ::std::fmt::Debug for EngagementSummary {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("EngagementSummary");
        formatter.field("arn", &self.arn);
        formatter.field("id", &self.id);
        formatter.field("title", &self.title);
        formatter.field("created_at", &self.created_at);
        formatter.field("created_by", &"*** Sensitive Data Redacted ***");
        formatter.field("member_count", &self.member_count);
        formatter.finish()
    }
}
impl EngagementSummary {
    /// Creates a new builder-style object to manufacture [`EngagementSummary`](crate::types::EngagementSummary).
    pub fn builder() -> crate::types::builders::EngagementSummaryBuilder {
        crate::types::builders::EngagementSummaryBuilder::default()
    }
}

/// A builder for [`EngagementSummary`](crate::types::EngagementSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct EngagementSummaryBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) title: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) created_by: ::std::option::Option<::std::string::String>,
    pub(crate) member_count: ::std::option::Option<i32>,
}
impl EngagementSummaryBuilder {
    /// <p>The Amazon Resource Name (ARN) of the created Engagement.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the created Engagement.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the created Engagement.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The unique identifier for the Engagement.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the Engagement.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique identifier for the Engagement.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The title of the Engagement.</p>
    pub fn title(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.title = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The title of the Engagement.</p>
    pub fn set_title(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.title = input;
        self
    }
    /// <p>The title of the Engagement.</p>
    pub fn get_title(&self) -> &::std::option::Option<::std::string::String> {
        &self.title
    }
    /// <p>The date and time when the Engagement was created.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time when the Engagement was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The date and time when the Engagement was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The AWS Account ID of the Engagement creator.</p>
    pub fn created_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.created_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The AWS Account ID of the Engagement creator.</p>
    pub fn set_created_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.created_by = input;
        self
    }
    /// <p>The AWS Account ID of the Engagement creator.</p>
    pub fn get_created_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.created_by
    }
    /// <p>The number of members in the Engagement.</p>
    pub fn member_count(mut self, input: i32) -> Self {
        self.member_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of members in the Engagement.</p>
    pub fn set_member_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.member_count = input;
        self
    }
    /// <p>The number of members in the Engagement.</p>
    pub fn get_member_count(&self) -> &::std::option::Option<i32> {
        &self.member_count
    }
    /// Consumes the builder and constructs a [`EngagementSummary`](crate::types::EngagementSummary).
    pub fn build(self) -> crate::types::EngagementSummary {
        crate::types::EngagementSummary {
            arn: self.arn,
            id: self.id,
            title: self.title,
            created_at: self.created_at,
            created_by: self.created_by,
            member_count: self.member_count,
        }
    }
}
impl ::std::fmt::Debug for EngagementSummaryBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("EngagementSummaryBuilder");
        formatter.field("arn", &self.arn);
        formatter.field("id", &self.id);
        formatter.field("title", &self.title);
        formatter.field("created_at", &self.created_at);
        formatter.field("created_by", &"*** Sensitive Data Redacted ***");
        formatter.field("member_count", &self.member_count);
        formatter.finish()
    }
}
