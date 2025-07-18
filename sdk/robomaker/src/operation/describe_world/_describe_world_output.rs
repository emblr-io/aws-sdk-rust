// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeWorldOutput {
    /// <p>The Amazon Resource Name (arn) of the world.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (arn) of the world generation job that generated the world.</p>
    pub generation_job: ::std::option::Option<::std::string::String>,
    /// <p>The world template.</p>
    pub template: ::std::option::Option<::std::string::String>,
    /// <p>The time, in milliseconds since the epoch, when the world was created.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A map that contains tag keys and tag values that are attached to the world.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>Returns the JSON formatted string that describes the contents of your world.</p>
    pub world_description_body: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeWorldOutput {
    /// <p>The Amazon Resource Name (arn) of the world.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The Amazon Resource Name (arn) of the world generation job that generated the world.</p>
    pub fn generation_job(&self) -> ::std::option::Option<&str> {
        self.generation_job.as_deref()
    }
    /// <p>The world template.</p>
    pub fn template(&self) -> ::std::option::Option<&str> {
        self.template.as_deref()
    }
    /// <p>The time, in milliseconds since the epoch, when the world was created.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>A map that contains tag keys and tag values that are attached to the world.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>Returns the JSON formatted string that describes the contents of your world.</p>
    pub fn world_description_body(&self) -> ::std::option::Option<&str> {
        self.world_description_body.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeWorldOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeWorldOutput {
    /// Creates a new builder-style object to manufacture [`DescribeWorldOutput`](crate::operation::describe_world::DescribeWorldOutput).
    pub fn builder() -> crate::operation::describe_world::builders::DescribeWorldOutputBuilder {
        crate::operation::describe_world::builders::DescribeWorldOutputBuilder::default()
    }
}

/// A builder for [`DescribeWorldOutput`](crate::operation::describe_world::DescribeWorldOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeWorldOutputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) generation_job: ::std::option::Option<::std::string::String>,
    pub(crate) template: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) world_description_body: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeWorldOutputBuilder {
    /// <p>The Amazon Resource Name (arn) of the world.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (arn) of the world.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (arn) of the world.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The Amazon Resource Name (arn) of the world generation job that generated the world.</p>
    pub fn generation_job(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.generation_job = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (arn) of the world generation job that generated the world.</p>
    pub fn set_generation_job(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.generation_job = input;
        self
    }
    /// <p>The Amazon Resource Name (arn) of the world generation job that generated the world.</p>
    pub fn get_generation_job(&self) -> &::std::option::Option<::std::string::String> {
        &self.generation_job
    }
    /// <p>The world template.</p>
    pub fn template(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The world template.</p>
    pub fn set_template(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template = input;
        self
    }
    /// <p>The world template.</p>
    pub fn get_template(&self) -> &::std::option::Option<::std::string::String> {
        &self.template
    }
    /// <p>The time, in milliseconds since the epoch, when the world was created.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time, in milliseconds since the epoch, when the world was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The time, in milliseconds since the epoch, when the world was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A map that contains tag keys and tag values that are attached to the world.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A map that contains tag keys and tag values that are attached to the world.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A map that contains tag keys and tag values that are attached to the world.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>Returns the JSON formatted string that describes the contents of your world.</p>
    pub fn world_description_body(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.world_description_body = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Returns the JSON formatted string that describes the contents of your world.</p>
    pub fn set_world_description_body(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.world_description_body = input;
        self
    }
    /// <p>Returns the JSON formatted string that describes the contents of your world.</p>
    pub fn get_world_description_body(&self) -> &::std::option::Option<::std::string::String> {
        &self.world_description_body
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeWorldOutput`](crate::operation::describe_world::DescribeWorldOutput).
    pub fn build(self) -> crate::operation::describe_world::DescribeWorldOutput {
        crate::operation::describe_world::DescribeWorldOutput {
            arn: self.arn,
            generation_job: self.generation_job,
            template: self.template,
            created_at: self.created_at,
            tags: self.tags,
            world_description_body: self.world_description_body,
            _request_id: self._request_id,
        }
    }
}
