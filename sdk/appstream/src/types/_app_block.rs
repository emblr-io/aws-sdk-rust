// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes an app block.</p>
/// <p>App blocks are an Amazon AppStream 2.0 resource that stores the details about the virtual hard disk in an S3 bucket. It also stores the setup script with details about how to mount the virtual hard disk. The virtual hard disk includes the application binaries and other files necessary to launch your applications. Multiple applications can be assigned to a single app block.</p>
/// <p>This is only supported for Elastic fleets.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AppBlock {
    /// <p>The name of the app block.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the app block.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The description of the app block.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The display name of the app block.</p>
    pub display_name: ::std::option::Option<::std::string::String>,
    /// <p>The source S3 location of the app block.</p>
    pub source_s3_location: ::std::option::Option<crate::types::S3Location>,
    /// <p>The setup script details of the app block.</p>
    /// <p>This only applies to app blocks with PackagingType <code>CUSTOM</code>.</p>
    pub setup_script_details: ::std::option::Option<crate::types::ScriptDetails>,
    /// <p>The created time of the app block.</p>
    pub created_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The post setup script details of the app block.</p>
    /// <p>This only applies to app blocks with PackagingType <code>APPSTREAM2</code>.</p>
    pub post_setup_script_details: ::std::option::Option<crate::types::ScriptDetails>,
    /// <p>The packaging type of the app block.</p>
    pub packaging_type: ::std::option::Option<crate::types::PackagingType>,
    /// <p>The state of the app block.</p>
    /// <p>An app block with AppStream 2.0 packaging will be in the <code>INACTIVE</code> state if no application package (VHD) is assigned to it. After an application package (VHD) is created by an app block builder for an app block, it becomes <code>ACTIVE</code>.</p>
    /// <p>Custom app blocks are always in the <code>ACTIVE</code> state and no action is required to use them.</p>
    pub state: ::std::option::Option<crate::types::AppBlockState>,
    /// <p>The errors of the app block.</p>
    pub app_block_errors: ::std::option::Option<::std::vec::Vec<crate::types::ErrorDetails>>,
}
impl AppBlock {
    /// <p>The name of the app block.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The ARN of the app block.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The description of the app block.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The display name of the app block.</p>
    pub fn display_name(&self) -> ::std::option::Option<&str> {
        self.display_name.as_deref()
    }
    /// <p>The source S3 location of the app block.</p>
    pub fn source_s3_location(&self) -> ::std::option::Option<&crate::types::S3Location> {
        self.source_s3_location.as_ref()
    }
    /// <p>The setup script details of the app block.</p>
    /// <p>This only applies to app blocks with PackagingType <code>CUSTOM</code>.</p>
    pub fn setup_script_details(&self) -> ::std::option::Option<&crate::types::ScriptDetails> {
        self.setup_script_details.as_ref()
    }
    /// <p>The created time of the app block.</p>
    pub fn created_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_time.as_ref()
    }
    /// <p>The post setup script details of the app block.</p>
    /// <p>This only applies to app blocks with PackagingType <code>APPSTREAM2</code>.</p>
    pub fn post_setup_script_details(&self) -> ::std::option::Option<&crate::types::ScriptDetails> {
        self.post_setup_script_details.as_ref()
    }
    /// <p>The packaging type of the app block.</p>
    pub fn packaging_type(&self) -> ::std::option::Option<&crate::types::PackagingType> {
        self.packaging_type.as_ref()
    }
    /// <p>The state of the app block.</p>
    /// <p>An app block with AppStream 2.0 packaging will be in the <code>INACTIVE</code> state if no application package (VHD) is assigned to it. After an application package (VHD) is created by an app block builder for an app block, it becomes <code>ACTIVE</code>.</p>
    /// <p>Custom app blocks are always in the <code>ACTIVE</code> state and no action is required to use them.</p>
    pub fn state(&self) -> ::std::option::Option<&crate::types::AppBlockState> {
        self.state.as_ref()
    }
    /// <p>The errors of the app block.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.app_block_errors.is_none()`.
    pub fn app_block_errors(&self) -> &[crate::types::ErrorDetails] {
        self.app_block_errors.as_deref().unwrap_or_default()
    }
}
impl AppBlock {
    /// Creates a new builder-style object to manufacture [`AppBlock`](crate::types::AppBlock).
    pub fn builder() -> crate::types::builders::AppBlockBuilder {
        crate::types::builders::AppBlockBuilder::default()
    }
}

/// A builder for [`AppBlock`](crate::types::AppBlock).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AppBlockBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) display_name: ::std::option::Option<::std::string::String>,
    pub(crate) source_s3_location: ::std::option::Option<crate::types::S3Location>,
    pub(crate) setup_script_details: ::std::option::Option<crate::types::ScriptDetails>,
    pub(crate) created_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) post_setup_script_details: ::std::option::Option<crate::types::ScriptDetails>,
    pub(crate) packaging_type: ::std::option::Option<crate::types::PackagingType>,
    pub(crate) state: ::std::option::Option<crate::types::AppBlockState>,
    pub(crate) app_block_errors: ::std::option::Option<::std::vec::Vec<crate::types::ErrorDetails>>,
}
impl AppBlockBuilder {
    /// <p>The name of the app block.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the app block.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the app block.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The ARN of the app block.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the app block.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The ARN of the app block.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The description of the app block.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the app block.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the app block.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The display name of the app block.</p>
    pub fn display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The display name of the app block.</p>
    pub fn set_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.display_name = input;
        self
    }
    /// <p>The display name of the app block.</p>
    pub fn get_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.display_name
    }
    /// <p>The source S3 location of the app block.</p>
    pub fn source_s3_location(mut self, input: crate::types::S3Location) -> Self {
        self.source_s3_location = ::std::option::Option::Some(input);
        self
    }
    /// <p>The source S3 location of the app block.</p>
    pub fn set_source_s3_location(mut self, input: ::std::option::Option<crate::types::S3Location>) -> Self {
        self.source_s3_location = input;
        self
    }
    /// <p>The source S3 location of the app block.</p>
    pub fn get_source_s3_location(&self) -> &::std::option::Option<crate::types::S3Location> {
        &self.source_s3_location
    }
    /// <p>The setup script details of the app block.</p>
    /// <p>This only applies to app blocks with PackagingType <code>CUSTOM</code>.</p>
    pub fn setup_script_details(mut self, input: crate::types::ScriptDetails) -> Self {
        self.setup_script_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>The setup script details of the app block.</p>
    /// <p>This only applies to app blocks with PackagingType <code>CUSTOM</code>.</p>
    pub fn set_setup_script_details(mut self, input: ::std::option::Option<crate::types::ScriptDetails>) -> Self {
        self.setup_script_details = input;
        self
    }
    /// <p>The setup script details of the app block.</p>
    /// <p>This only applies to app blocks with PackagingType <code>CUSTOM</code>.</p>
    pub fn get_setup_script_details(&self) -> &::std::option::Option<crate::types::ScriptDetails> {
        &self.setup_script_details
    }
    /// <p>The created time of the app block.</p>
    pub fn created_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The created time of the app block.</p>
    pub fn set_created_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_time = input;
        self
    }
    /// <p>The created time of the app block.</p>
    pub fn get_created_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_time
    }
    /// <p>The post setup script details of the app block.</p>
    /// <p>This only applies to app blocks with PackagingType <code>APPSTREAM2</code>.</p>
    pub fn post_setup_script_details(mut self, input: crate::types::ScriptDetails) -> Self {
        self.post_setup_script_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>The post setup script details of the app block.</p>
    /// <p>This only applies to app blocks with PackagingType <code>APPSTREAM2</code>.</p>
    pub fn set_post_setup_script_details(mut self, input: ::std::option::Option<crate::types::ScriptDetails>) -> Self {
        self.post_setup_script_details = input;
        self
    }
    /// <p>The post setup script details of the app block.</p>
    /// <p>This only applies to app blocks with PackagingType <code>APPSTREAM2</code>.</p>
    pub fn get_post_setup_script_details(&self) -> &::std::option::Option<crate::types::ScriptDetails> {
        &self.post_setup_script_details
    }
    /// <p>The packaging type of the app block.</p>
    pub fn packaging_type(mut self, input: crate::types::PackagingType) -> Self {
        self.packaging_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The packaging type of the app block.</p>
    pub fn set_packaging_type(mut self, input: ::std::option::Option<crate::types::PackagingType>) -> Self {
        self.packaging_type = input;
        self
    }
    /// <p>The packaging type of the app block.</p>
    pub fn get_packaging_type(&self) -> &::std::option::Option<crate::types::PackagingType> {
        &self.packaging_type
    }
    /// <p>The state of the app block.</p>
    /// <p>An app block with AppStream 2.0 packaging will be in the <code>INACTIVE</code> state if no application package (VHD) is assigned to it. After an application package (VHD) is created by an app block builder for an app block, it becomes <code>ACTIVE</code>.</p>
    /// <p>Custom app blocks are always in the <code>ACTIVE</code> state and no action is required to use them.</p>
    pub fn state(mut self, input: crate::types::AppBlockState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The state of the app block.</p>
    /// <p>An app block with AppStream 2.0 packaging will be in the <code>INACTIVE</code> state if no application package (VHD) is assigned to it. After an application package (VHD) is created by an app block builder for an app block, it becomes <code>ACTIVE</code>.</p>
    /// <p>Custom app blocks are always in the <code>ACTIVE</code> state and no action is required to use them.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::AppBlockState>) -> Self {
        self.state = input;
        self
    }
    /// <p>The state of the app block.</p>
    /// <p>An app block with AppStream 2.0 packaging will be in the <code>INACTIVE</code> state if no application package (VHD) is assigned to it. After an application package (VHD) is created by an app block builder for an app block, it becomes <code>ACTIVE</code>.</p>
    /// <p>Custom app blocks are always in the <code>ACTIVE</code> state and no action is required to use them.</p>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::AppBlockState> {
        &self.state
    }
    /// Appends an item to `app_block_errors`.
    ///
    /// To override the contents of this collection use [`set_app_block_errors`](Self::set_app_block_errors).
    ///
    /// <p>The errors of the app block.</p>
    pub fn app_block_errors(mut self, input: crate::types::ErrorDetails) -> Self {
        let mut v = self.app_block_errors.unwrap_or_default();
        v.push(input);
        self.app_block_errors = ::std::option::Option::Some(v);
        self
    }
    /// <p>The errors of the app block.</p>
    pub fn set_app_block_errors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ErrorDetails>>) -> Self {
        self.app_block_errors = input;
        self
    }
    /// <p>The errors of the app block.</p>
    pub fn get_app_block_errors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ErrorDetails>> {
        &self.app_block_errors
    }
    /// Consumes the builder and constructs a [`AppBlock`](crate::types::AppBlock).
    pub fn build(self) -> crate::types::AppBlock {
        crate::types::AppBlock {
            name: self.name,
            arn: self.arn,
            description: self.description,
            display_name: self.display_name,
            source_s3_location: self.source_s3_location,
            setup_script_details: self.setup_script_details,
            created_time: self.created_time,
            post_setup_script_details: self.post_setup_script_details,
            packaging_type: self.packaging_type,
            state: self.state,
            app_block_errors: self.app_block_errors,
        }
    }
}
