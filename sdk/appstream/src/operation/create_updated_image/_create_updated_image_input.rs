// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateUpdatedImageInput {
    /// <p>The name of the image to update.</p>
    pub existing_image_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the new image. The name must be unique within the AWS account and Region.</p>
    pub new_image_name: ::std::option::Option<::std::string::String>,
    /// <p>The description to display for the new image.</p>
    pub new_image_description: ::std::option::Option<::std::string::String>,
    /// <p>The name to display for the new image.</p>
    pub new_image_display_name: ::std::option::Option<::std::string::String>,
    /// <p>The tags to associate with the new image. A tag is a key-value pair, and the value is optional. For example, Environment=Test. If you do not specify a value, Environment=.</p>
    /// <p>Generally allowed characters are: letters, numbers, and spaces representable in UTF-8, and the following special characters:</p>
    /// <p>_ . : / = + \ - @</p>
    /// <p>If you do not specify a value, the value is set to an empty string.</p>
    /// <p>For more information about tags, see <a href="https://docs.aws.amazon.com/appstream2/latest/developerguide/tagging-basic.html">Tagging Your Resources</a> in the <i>Amazon AppStream 2.0 Administration Guide</i>.</p>
    pub new_image_tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>Indicates whether to display the status of image update availability before AppStream 2.0 initiates the process of creating a new updated image. If this value is set to <code>true</code>, AppStream 2.0 displays whether image updates are available. If this value is set to <code>false</code>, AppStream 2.0 initiates the process of creating a new updated image without displaying whether image updates are available.</p>
    pub dry_run: ::std::option::Option<bool>,
}
impl CreateUpdatedImageInput {
    /// <p>The name of the image to update.</p>
    pub fn existing_image_name(&self) -> ::std::option::Option<&str> {
        self.existing_image_name.as_deref()
    }
    /// <p>The name of the new image. The name must be unique within the AWS account and Region.</p>
    pub fn new_image_name(&self) -> ::std::option::Option<&str> {
        self.new_image_name.as_deref()
    }
    /// <p>The description to display for the new image.</p>
    pub fn new_image_description(&self) -> ::std::option::Option<&str> {
        self.new_image_description.as_deref()
    }
    /// <p>The name to display for the new image.</p>
    pub fn new_image_display_name(&self) -> ::std::option::Option<&str> {
        self.new_image_display_name.as_deref()
    }
    /// <p>The tags to associate with the new image. A tag is a key-value pair, and the value is optional. For example, Environment=Test. If you do not specify a value, Environment=.</p>
    /// <p>Generally allowed characters are: letters, numbers, and spaces representable in UTF-8, and the following special characters:</p>
    /// <p>_ . : / = + \ - @</p>
    /// <p>If you do not specify a value, the value is set to an empty string.</p>
    /// <p>For more information about tags, see <a href="https://docs.aws.amazon.com/appstream2/latest/developerguide/tagging-basic.html">Tagging Your Resources</a> in the <i>Amazon AppStream 2.0 Administration Guide</i>.</p>
    pub fn new_image_tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.new_image_tags.as_ref()
    }
    /// <p>Indicates whether to display the status of image update availability before AppStream 2.0 initiates the process of creating a new updated image. If this value is set to <code>true</code>, AppStream 2.0 displays whether image updates are available. If this value is set to <code>false</code>, AppStream 2.0 initiates the process of creating a new updated image without displaying whether image updates are available.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
}
impl CreateUpdatedImageInput {
    /// Creates a new builder-style object to manufacture [`CreateUpdatedImageInput`](crate::operation::create_updated_image::CreateUpdatedImageInput).
    pub fn builder() -> crate::operation::create_updated_image::builders::CreateUpdatedImageInputBuilder {
        crate::operation::create_updated_image::builders::CreateUpdatedImageInputBuilder::default()
    }
}

/// A builder for [`CreateUpdatedImageInput`](crate::operation::create_updated_image::CreateUpdatedImageInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateUpdatedImageInputBuilder {
    pub(crate) existing_image_name: ::std::option::Option<::std::string::String>,
    pub(crate) new_image_name: ::std::option::Option<::std::string::String>,
    pub(crate) new_image_description: ::std::option::Option<::std::string::String>,
    pub(crate) new_image_display_name: ::std::option::Option<::std::string::String>,
    pub(crate) new_image_tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) dry_run: ::std::option::Option<bool>,
}
impl CreateUpdatedImageInputBuilder {
    /// <p>The name of the image to update.</p>
    /// This field is required.
    pub fn existing_image_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.existing_image_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the image to update.</p>
    pub fn set_existing_image_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.existing_image_name = input;
        self
    }
    /// <p>The name of the image to update.</p>
    pub fn get_existing_image_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.existing_image_name
    }
    /// <p>The name of the new image. The name must be unique within the AWS account and Region.</p>
    /// This field is required.
    pub fn new_image_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.new_image_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the new image. The name must be unique within the AWS account and Region.</p>
    pub fn set_new_image_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.new_image_name = input;
        self
    }
    /// <p>The name of the new image. The name must be unique within the AWS account and Region.</p>
    pub fn get_new_image_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.new_image_name
    }
    /// <p>The description to display for the new image.</p>
    pub fn new_image_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.new_image_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description to display for the new image.</p>
    pub fn set_new_image_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.new_image_description = input;
        self
    }
    /// <p>The description to display for the new image.</p>
    pub fn get_new_image_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.new_image_description
    }
    /// <p>The name to display for the new image.</p>
    pub fn new_image_display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.new_image_display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name to display for the new image.</p>
    pub fn set_new_image_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.new_image_display_name = input;
        self
    }
    /// <p>The name to display for the new image.</p>
    pub fn get_new_image_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.new_image_display_name
    }
    /// Adds a key-value pair to `new_image_tags`.
    ///
    /// To override the contents of this collection use [`set_new_image_tags`](Self::set_new_image_tags).
    ///
    /// <p>The tags to associate with the new image. A tag is a key-value pair, and the value is optional. For example, Environment=Test. If you do not specify a value, Environment=.</p>
    /// <p>Generally allowed characters are: letters, numbers, and spaces representable in UTF-8, and the following special characters:</p>
    /// <p>_ . : / = + \ - @</p>
    /// <p>If you do not specify a value, the value is set to an empty string.</p>
    /// <p>For more information about tags, see <a href="https://docs.aws.amazon.com/appstream2/latest/developerguide/tagging-basic.html">Tagging Your Resources</a> in the <i>Amazon AppStream 2.0 Administration Guide</i>.</p>
    pub fn new_image_tags(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.new_image_tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.new_image_tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags to associate with the new image. A tag is a key-value pair, and the value is optional. For example, Environment=Test. If you do not specify a value, Environment=.</p>
    /// <p>Generally allowed characters are: letters, numbers, and spaces representable in UTF-8, and the following special characters:</p>
    /// <p>_ . : / = + \ - @</p>
    /// <p>If you do not specify a value, the value is set to an empty string.</p>
    /// <p>For more information about tags, see <a href="https://docs.aws.amazon.com/appstream2/latest/developerguide/tagging-basic.html">Tagging Your Resources</a> in the <i>Amazon AppStream 2.0 Administration Guide</i>.</p>
    pub fn set_new_image_tags(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.new_image_tags = input;
        self
    }
    /// <p>The tags to associate with the new image. A tag is a key-value pair, and the value is optional. For example, Environment=Test. If you do not specify a value, Environment=.</p>
    /// <p>Generally allowed characters are: letters, numbers, and spaces representable in UTF-8, and the following special characters:</p>
    /// <p>_ . : / = + \ - @</p>
    /// <p>If you do not specify a value, the value is set to an empty string.</p>
    /// <p>For more information about tags, see <a href="https://docs.aws.amazon.com/appstream2/latest/developerguide/tagging-basic.html">Tagging Your Resources</a> in the <i>Amazon AppStream 2.0 Administration Guide</i>.</p>
    pub fn get_new_image_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.new_image_tags
    }
    /// <p>Indicates whether to display the status of image update availability before AppStream 2.0 initiates the process of creating a new updated image. If this value is set to <code>true</code>, AppStream 2.0 displays whether image updates are available. If this value is set to <code>false</code>, AppStream 2.0 initiates the process of creating a new updated image without displaying whether image updates are available.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.dry_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether to display the status of image update availability before AppStream 2.0 initiates the process of creating a new updated image. If this value is set to <code>true</code>, AppStream 2.0 displays whether image updates are available. If this value is set to <code>false</code>, AppStream 2.0 initiates the process of creating a new updated image without displaying whether image updates are available.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dry_run = input;
        self
    }
    /// <p>Indicates whether to display the status of image update availability before AppStream 2.0 initiates the process of creating a new updated image. If this value is set to <code>true</code>, AppStream 2.0 displays whether image updates are available. If this value is set to <code>false</code>, AppStream 2.0 initiates the process of creating a new updated image without displaying whether image updates are available.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        &self.dry_run
    }
    /// Consumes the builder and constructs a [`CreateUpdatedImageInput`](crate::operation::create_updated_image::CreateUpdatedImageInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_updated_image::CreateUpdatedImageInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_updated_image::CreateUpdatedImageInput {
            existing_image_name: self.existing_image_name,
            new_image_name: self.new_image_name,
            new_image_description: self.new_image_description,
            new_image_display_name: self.new_image_display_name,
            new_image_tags: self.new_image_tags,
            dry_run: self.dry_run,
        })
    }
}
