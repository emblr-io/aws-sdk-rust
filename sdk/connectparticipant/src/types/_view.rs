// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A view resource object. Contains metadata and content necessary to render the view.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct View {
    /// <p>The identifier of the view.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the view.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the view.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The current version of the view.</p>
    pub version: ::std::option::Option<i32>,
    /// <p>View content containing all content necessary to render a view except for runtime input data.</p>
    pub content: ::std::option::Option<crate::types::ViewContent>,
}
impl View {
    /// <p>The identifier of the view.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the view.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The name of the view.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The current version of the view.</p>
    pub fn version(&self) -> ::std::option::Option<i32> {
        self.version
    }
    /// <p>View content containing all content necessary to render a view except for runtime input data.</p>
    pub fn content(&self) -> ::std::option::Option<&crate::types::ViewContent> {
        self.content.as_ref()
    }
}
impl ::std::fmt::Debug for View {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("View");
        formatter.field("id", &self.id);
        formatter.field("arn", &self.arn);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("version", &self.version);
        formatter.field("content", &self.content);
        formatter.finish()
    }
}
impl View {
    /// Creates a new builder-style object to manufacture [`View`](crate::types::View).
    pub fn builder() -> crate::types::builders::ViewBuilder {
        crate::types::builders::ViewBuilder::default()
    }
}

/// A builder for [`View`](crate::types::View).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct ViewBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) version: ::std::option::Option<i32>,
    pub(crate) content: ::std::option::Option<crate::types::ViewContent>,
}
impl ViewBuilder {
    /// <p>The identifier of the view.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the view.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The identifier of the view.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The Amazon Resource Name (ARN) of the view.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the view.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the view.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The name of the view.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the view.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the view.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The current version of the view.</p>
    pub fn version(mut self, input: i32) -> Self {
        self.version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current version of the view.</p>
    pub fn set_version(mut self, input: ::std::option::Option<i32>) -> Self {
        self.version = input;
        self
    }
    /// <p>The current version of the view.</p>
    pub fn get_version(&self) -> &::std::option::Option<i32> {
        &self.version
    }
    /// <p>View content containing all content necessary to render a view except for runtime input data.</p>
    pub fn content(mut self, input: crate::types::ViewContent) -> Self {
        self.content = ::std::option::Option::Some(input);
        self
    }
    /// <p>View content containing all content necessary to render a view except for runtime input data.</p>
    pub fn set_content(mut self, input: ::std::option::Option<crate::types::ViewContent>) -> Self {
        self.content = input;
        self
    }
    /// <p>View content containing all content necessary to render a view except for runtime input data.</p>
    pub fn get_content(&self) -> &::std::option::Option<crate::types::ViewContent> {
        &self.content
    }
    /// Consumes the builder and constructs a [`View`](crate::types::View).
    pub fn build(self) -> crate::types::View {
        crate::types::View {
            id: self.id,
            arn: self.arn,
            name: self.name,
            version: self.version,
            content: self.content,
        }
    }
}
impl ::std::fmt::Debug for ViewBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ViewBuilder");
        formatter.field("id", &self.id);
        formatter.field("arn", &self.arn);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("version", &self.version);
        formatter.field("content", &self.content);
        formatter.finish()
    }
}
