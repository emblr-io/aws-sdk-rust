// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateLaunchConfigurationInput {
    /// <p>Update Launch configuration by Source Server ID request.</p>
    pub source_server_id: ::std::option::Option<::std::string::String>,
    /// <p>Update Launch configuration name request.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Update Launch configuration launch disposition request.</p>
    pub launch_disposition: ::std::option::Option<crate::types::LaunchDisposition>,
    /// <p>Update Launch configuration Target instance right sizing request.</p>
    pub target_instance_type_right_sizing_method: ::std::option::Option<crate::types::TargetInstanceTypeRightSizingMethod>,
    /// <p>Update Launch configuration copy Private IP request.</p>
    pub copy_private_ip: ::std::option::Option<bool>,
    /// <p>Update Launch configuration copy Tags request.</p>
    pub copy_tags: ::std::option::Option<bool>,
    /// <p>Update Launch configuration licensing request.</p>
    pub licensing: ::std::option::Option<crate::types::Licensing>,
    /// <p>Update Launch configuration boot mode request.</p>
    pub boot_mode: ::std::option::Option<crate::types::BootMode>,
    /// <p>Post Launch Actions to executed on the Test or Cutover instance.</p>
    pub post_launch_actions: ::std::option::Option<crate::types::PostLaunchActions>,
    /// <p>Enable map auto tagging.</p>
    pub enable_map_auto_tagging: ::std::option::Option<bool>,
    /// <p>Launch configuration map auto tagging MPE ID.</p>
    pub map_auto_tagging_mpe_id: ::std::option::Option<::std::string::String>,
    /// <p>Update Launch configuration Account ID.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
}
impl UpdateLaunchConfigurationInput {
    /// <p>Update Launch configuration by Source Server ID request.</p>
    pub fn source_server_id(&self) -> ::std::option::Option<&str> {
        self.source_server_id.as_deref()
    }
    /// <p>Update Launch configuration name request.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Update Launch configuration launch disposition request.</p>
    pub fn launch_disposition(&self) -> ::std::option::Option<&crate::types::LaunchDisposition> {
        self.launch_disposition.as_ref()
    }
    /// <p>Update Launch configuration Target instance right sizing request.</p>
    pub fn target_instance_type_right_sizing_method(&self) -> ::std::option::Option<&crate::types::TargetInstanceTypeRightSizingMethod> {
        self.target_instance_type_right_sizing_method.as_ref()
    }
    /// <p>Update Launch configuration copy Private IP request.</p>
    pub fn copy_private_ip(&self) -> ::std::option::Option<bool> {
        self.copy_private_ip
    }
    /// <p>Update Launch configuration copy Tags request.</p>
    pub fn copy_tags(&self) -> ::std::option::Option<bool> {
        self.copy_tags
    }
    /// <p>Update Launch configuration licensing request.</p>
    pub fn licensing(&self) -> ::std::option::Option<&crate::types::Licensing> {
        self.licensing.as_ref()
    }
    /// <p>Update Launch configuration boot mode request.</p>
    pub fn boot_mode(&self) -> ::std::option::Option<&crate::types::BootMode> {
        self.boot_mode.as_ref()
    }
    /// <p>Post Launch Actions to executed on the Test or Cutover instance.</p>
    pub fn post_launch_actions(&self) -> ::std::option::Option<&crate::types::PostLaunchActions> {
        self.post_launch_actions.as_ref()
    }
    /// <p>Enable map auto tagging.</p>
    pub fn enable_map_auto_tagging(&self) -> ::std::option::Option<bool> {
        self.enable_map_auto_tagging
    }
    /// <p>Launch configuration map auto tagging MPE ID.</p>
    pub fn map_auto_tagging_mpe_id(&self) -> ::std::option::Option<&str> {
        self.map_auto_tagging_mpe_id.as_deref()
    }
    /// <p>Update Launch configuration Account ID.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
}
impl UpdateLaunchConfigurationInput {
    /// Creates a new builder-style object to manufacture [`UpdateLaunchConfigurationInput`](crate::operation::update_launch_configuration::UpdateLaunchConfigurationInput).
    pub fn builder() -> crate::operation::update_launch_configuration::builders::UpdateLaunchConfigurationInputBuilder {
        crate::operation::update_launch_configuration::builders::UpdateLaunchConfigurationInputBuilder::default()
    }
}

/// A builder for [`UpdateLaunchConfigurationInput`](crate::operation::update_launch_configuration::UpdateLaunchConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateLaunchConfigurationInputBuilder {
    pub(crate) source_server_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) launch_disposition: ::std::option::Option<crate::types::LaunchDisposition>,
    pub(crate) target_instance_type_right_sizing_method: ::std::option::Option<crate::types::TargetInstanceTypeRightSizingMethod>,
    pub(crate) copy_private_ip: ::std::option::Option<bool>,
    pub(crate) copy_tags: ::std::option::Option<bool>,
    pub(crate) licensing: ::std::option::Option<crate::types::Licensing>,
    pub(crate) boot_mode: ::std::option::Option<crate::types::BootMode>,
    pub(crate) post_launch_actions: ::std::option::Option<crate::types::PostLaunchActions>,
    pub(crate) enable_map_auto_tagging: ::std::option::Option<bool>,
    pub(crate) map_auto_tagging_mpe_id: ::std::option::Option<::std::string::String>,
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
}
impl UpdateLaunchConfigurationInputBuilder {
    /// <p>Update Launch configuration by Source Server ID request.</p>
    /// This field is required.
    pub fn source_server_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_server_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Update Launch configuration by Source Server ID request.</p>
    pub fn set_source_server_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_server_id = input;
        self
    }
    /// <p>Update Launch configuration by Source Server ID request.</p>
    pub fn get_source_server_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_server_id
    }
    /// <p>Update Launch configuration name request.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Update Launch configuration name request.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>Update Launch configuration name request.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Update Launch configuration launch disposition request.</p>
    pub fn launch_disposition(mut self, input: crate::types::LaunchDisposition) -> Self {
        self.launch_disposition = ::std::option::Option::Some(input);
        self
    }
    /// <p>Update Launch configuration launch disposition request.</p>
    pub fn set_launch_disposition(mut self, input: ::std::option::Option<crate::types::LaunchDisposition>) -> Self {
        self.launch_disposition = input;
        self
    }
    /// <p>Update Launch configuration launch disposition request.</p>
    pub fn get_launch_disposition(&self) -> &::std::option::Option<crate::types::LaunchDisposition> {
        &self.launch_disposition
    }
    /// <p>Update Launch configuration Target instance right sizing request.</p>
    pub fn target_instance_type_right_sizing_method(mut self, input: crate::types::TargetInstanceTypeRightSizingMethod) -> Self {
        self.target_instance_type_right_sizing_method = ::std::option::Option::Some(input);
        self
    }
    /// <p>Update Launch configuration Target instance right sizing request.</p>
    pub fn set_target_instance_type_right_sizing_method(
        mut self,
        input: ::std::option::Option<crate::types::TargetInstanceTypeRightSizingMethod>,
    ) -> Self {
        self.target_instance_type_right_sizing_method = input;
        self
    }
    /// <p>Update Launch configuration Target instance right sizing request.</p>
    pub fn get_target_instance_type_right_sizing_method(&self) -> &::std::option::Option<crate::types::TargetInstanceTypeRightSizingMethod> {
        &self.target_instance_type_right_sizing_method
    }
    /// <p>Update Launch configuration copy Private IP request.</p>
    pub fn copy_private_ip(mut self, input: bool) -> Self {
        self.copy_private_ip = ::std::option::Option::Some(input);
        self
    }
    /// <p>Update Launch configuration copy Private IP request.</p>
    pub fn set_copy_private_ip(mut self, input: ::std::option::Option<bool>) -> Self {
        self.copy_private_ip = input;
        self
    }
    /// <p>Update Launch configuration copy Private IP request.</p>
    pub fn get_copy_private_ip(&self) -> &::std::option::Option<bool> {
        &self.copy_private_ip
    }
    /// <p>Update Launch configuration copy Tags request.</p>
    pub fn copy_tags(mut self, input: bool) -> Self {
        self.copy_tags = ::std::option::Option::Some(input);
        self
    }
    /// <p>Update Launch configuration copy Tags request.</p>
    pub fn set_copy_tags(mut self, input: ::std::option::Option<bool>) -> Self {
        self.copy_tags = input;
        self
    }
    /// <p>Update Launch configuration copy Tags request.</p>
    pub fn get_copy_tags(&self) -> &::std::option::Option<bool> {
        &self.copy_tags
    }
    /// <p>Update Launch configuration licensing request.</p>
    pub fn licensing(mut self, input: crate::types::Licensing) -> Self {
        self.licensing = ::std::option::Option::Some(input);
        self
    }
    /// <p>Update Launch configuration licensing request.</p>
    pub fn set_licensing(mut self, input: ::std::option::Option<crate::types::Licensing>) -> Self {
        self.licensing = input;
        self
    }
    /// <p>Update Launch configuration licensing request.</p>
    pub fn get_licensing(&self) -> &::std::option::Option<crate::types::Licensing> {
        &self.licensing
    }
    /// <p>Update Launch configuration boot mode request.</p>
    pub fn boot_mode(mut self, input: crate::types::BootMode) -> Self {
        self.boot_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>Update Launch configuration boot mode request.</p>
    pub fn set_boot_mode(mut self, input: ::std::option::Option<crate::types::BootMode>) -> Self {
        self.boot_mode = input;
        self
    }
    /// <p>Update Launch configuration boot mode request.</p>
    pub fn get_boot_mode(&self) -> &::std::option::Option<crate::types::BootMode> {
        &self.boot_mode
    }
    /// <p>Post Launch Actions to executed on the Test or Cutover instance.</p>
    pub fn post_launch_actions(mut self, input: crate::types::PostLaunchActions) -> Self {
        self.post_launch_actions = ::std::option::Option::Some(input);
        self
    }
    /// <p>Post Launch Actions to executed on the Test or Cutover instance.</p>
    pub fn set_post_launch_actions(mut self, input: ::std::option::Option<crate::types::PostLaunchActions>) -> Self {
        self.post_launch_actions = input;
        self
    }
    /// <p>Post Launch Actions to executed on the Test or Cutover instance.</p>
    pub fn get_post_launch_actions(&self) -> &::std::option::Option<crate::types::PostLaunchActions> {
        &self.post_launch_actions
    }
    /// <p>Enable map auto tagging.</p>
    pub fn enable_map_auto_tagging(mut self, input: bool) -> Self {
        self.enable_map_auto_tagging = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enable map auto tagging.</p>
    pub fn set_enable_map_auto_tagging(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enable_map_auto_tagging = input;
        self
    }
    /// <p>Enable map auto tagging.</p>
    pub fn get_enable_map_auto_tagging(&self) -> &::std::option::Option<bool> {
        &self.enable_map_auto_tagging
    }
    /// <p>Launch configuration map auto tagging MPE ID.</p>
    pub fn map_auto_tagging_mpe_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.map_auto_tagging_mpe_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Launch configuration map auto tagging MPE ID.</p>
    pub fn set_map_auto_tagging_mpe_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.map_auto_tagging_mpe_id = input;
        self
    }
    /// <p>Launch configuration map auto tagging MPE ID.</p>
    pub fn get_map_auto_tagging_mpe_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.map_auto_tagging_mpe_id
    }
    /// <p>Update Launch configuration Account ID.</p>
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Update Launch configuration Account ID.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>Update Launch configuration Account ID.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// Consumes the builder and constructs a [`UpdateLaunchConfigurationInput`](crate::operation::update_launch_configuration::UpdateLaunchConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_launch_configuration::UpdateLaunchConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_launch_configuration::UpdateLaunchConfigurationInput {
            source_server_id: self.source_server_id,
            name: self.name,
            launch_disposition: self.launch_disposition,
            target_instance_type_right_sizing_method: self.target_instance_type_right_sizing_method,
            copy_private_ip: self.copy_private_ip,
            copy_tags: self.copy_tags,
            licensing: self.licensing,
            boot_mode: self.boot_mode,
            post_launch_actions: self.post_launch_actions,
            enable_map_auto_tagging: self.enable_map_auto_tagging,
            map_auto_tagging_mpe_id: self.map_auto_tagging_mpe_id,
            account_id: self.account_id,
        })
    }
}
