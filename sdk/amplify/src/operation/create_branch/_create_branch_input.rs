// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The request structure for the create branch request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct CreateBranchInput {
    /// <p>The unique ID for an Amplify app.</p>
    pub app_id: ::std::option::Option<::std::string::String>,
    /// <p>The name for the branch.</p>
    pub branch_name: ::std::option::Option<::std::string::String>,
    /// <p>The description for the branch.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Describes the current stage for the branch.</p>
    pub stage: ::std::option::Option<crate::types::Stage>,
    /// <p>The framework for the branch.</p>
    pub framework: ::std::option::Option<::std::string::String>,
    /// <p>Enables notifications for the branch.</p>
    pub enable_notification: ::std::option::Option<bool>,
    /// <p>Enables auto building for the branch.</p>
    pub enable_auto_build: ::std::option::Option<bool>,
    /// <p>Specifies whether the skew protection feature is enabled for the branch.</p>
    /// <p>Deployment skew protection is available to Amplify applications to eliminate version skew issues between client and servers in web applications. When you apply skew protection to a branch, you can ensure that your clients always interact with the correct version of server-side assets, regardless of when a deployment occurs. For more information about skew protection, see <a href="https://docs.aws.amazon.com/amplify/latest/userguide/skew-protection.html">Skew protection for Amplify deployments</a> in the <i>Amplify User Guide</i>.</p>
    pub enable_skew_protection: ::std::option::Option<bool>,
    /// <p>The environment variables for the branch.</p>
    pub environment_variables: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The basic authorization credentials for the branch. You must base64-encode the authorization credentials and provide them in the format <code>user:password</code>.</p>
    pub basic_auth_credentials: ::std::option::Option<::std::string::String>,
    /// <p>Enables basic authorization for the branch.</p>
    pub enable_basic_auth: ::std::option::Option<bool>,
    /// <p>Enables performance mode for the branch.</p>
    /// <p>Performance mode optimizes for faster hosting performance by keeping content cached at the edge for a longer interval. When performance mode is enabled, hosting configuration or code changes can take up to 10 minutes to roll out.</p>
    pub enable_performance_mode: ::std::option::Option<bool>,
    /// <p>The tag for the branch.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The build specification (build spec) for the branch.</p>
    pub build_spec: ::std::option::Option<::std::string::String>,
    /// <p>The content Time To Live (TTL) for the website in seconds.</p>
    pub ttl: ::std::option::Option<::std::string::String>,
    /// <p>The display name for a branch. This is used as the default domain prefix.</p>
    pub display_name: ::std::option::Option<::std::string::String>,
    /// <p>Enables pull request previews for this branch.</p>
    pub enable_pull_request_preview: ::std::option::Option<bool>,
    /// <p>The Amplify environment name for the pull request.</p>
    pub pull_request_environment_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) for a backend environment that is part of a Gen 1 Amplify app.</p>
    /// <p>This field is available to Amplify Gen 1 apps only where the backend is created using Amplify Studio or the Amplify command line interface (CLI).</p>
    pub backend_environment_arn: ::std::option::Option<::std::string::String>,
    /// <p>The backend for a <code>Branch</code> of an Amplify app. Use for a backend created from an CloudFormation stack.</p>
    /// <p>This field is available to Amplify Gen 2 apps only. When you deploy an application with Amplify Gen 2, you provision the app's backend infrastructure using Typescript code.</p>
    pub backend: ::std::option::Option<crate::types::Backend>,
    /// <p>The Amazon Resource Name (ARN) of the IAM role to assign to a branch of an SSR app. The SSR Compute role allows the Amplify Hosting compute service to securely access specific Amazon Web Services resources based on the role's permissions. For more information about the SSR Compute role, see <a href="https://docs.aws.amazon.com/amplify/latest/userguide/amplify-SSR-compute-role.html">Adding an SSR Compute role</a> in the <i>Amplify User Guide</i>.</p>
    pub compute_role_arn: ::std::option::Option<::std::string::String>,
}
impl CreateBranchInput {
    /// <p>The unique ID for an Amplify app.</p>
    pub fn app_id(&self) -> ::std::option::Option<&str> {
        self.app_id.as_deref()
    }
    /// <p>The name for the branch.</p>
    pub fn branch_name(&self) -> ::std::option::Option<&str> {
        self.branch_name.as_deref()
    }
    /// <p>The description for the branch.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Describes the current stage for the branch.</p>
    pub fn stage(&self) -> ::std::option::Option<&crate::types::Stage> {
        self.stage.as_ref()
    }
    /// <p>The framework for the branch.</p>
    pub fn framework(&self) -> ::std::option::Option<&str> {
        self.framework.as_deref()
    }
    /// <p>Enables notifications for the branch.</p>
    pub fn enable_notification(&self) -> ::std::option::Option<bool> {
        self.enable_notification
    }
    /// <p>Enables auto building for the branch.</p>
    pub fn enable_auto_build(&self) -> ::std::option::Option<bool> {
        self.enable_auto_build
    }
    /// <p>Specifies whether the skew protection feature is enabled for the branch.</p>
    /// <p>Deployment skew protection is available to Amplify applications to eliminate version skew issues between client and servers in web applications. When you apply skew protection to a branch, you can ensure that your clients always interact with the correct version of server-side assets, regardless of when a deployment occurs. For more information about skew protection, see <a href="https://docs.aws.amazon.com/amplify/latest/userguide/skew-protection.html">Skew protection for Amplify deployments</a> in the <i>Amplify User Guide</i>.</p>
    pub fn enable_skew_protection(&self) -> ::std::option::Option<bool> {
        self.enable_skew_protection
    }
    /// <p>The environment variables for the branch.</p>
    pub fn environment_variables(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.environment_variables.as_ref()
    }
    /// <p>The basic authorization credentials for the branch. You must base64-encode the authorization credentials and provide them in the format <code>user:password</code>.</p>
    pub fn basic_auth_credentials(&self) -> ::std::option::Option<&str> {
        self.basic_auth_credentials.as_deref()
    }
    /// <p>Enables basic authorization for the branch.</p>
    pub fn enable_basic_auth(&self) -> ::std::option::Option<bool> {
        self.enable_basic_auth
    }
    /// <p>Enables performance mode for the branch.</p>
    /// <p>Performance mode optimizes for faster hosting performance by keeping content cached at the edge for a longer interval. When performance mode is enabled, hosting configuration or code changes can take up to 10 minutes to roll out.</p>
    pub fn enable_performance_mode(&self) -> ::std::option::Option<bool> {
        self.enable_performance_mode
    }
    /// <p>The tag for the branch.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>The build specification (build spec) for the branch.</p>
    pub fn build_spec(&self) -> ::std::option::Option<&str> {
        self.build_spec.as_deref()
    }
    /// <p>The content Time To Live (TTL) for the website in seconds.</p>
    pub fn ttl(&self) -> ::std::option::Option<&str> {
        self.ttl.as_deref()
    }
    /// <p>The display name for a branch. This is used as the default domain prefix.</p>
    pub fn display_name(&self) -> ::std::option::Option<&str> {
        self.display_name.as_deref()
    }
    /// <p>Enables pull request previews for this branch.</p>
    pub fn enable_pull_request_preview(&self) -> ::std::option::Option<bool> {
        self.enable_pull_request_preview
    }
    /// <p>The Amplify environment name for the pull request.</p>
    pub fn pull_request_environment_name(&self) -> ::std::option::Option<&str> {
        self.pull_request_environment_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) for a backend environment that is part of a Gen 1 Amplify app.</p>
    /// <p>This field is available to Amplify Gen 1 apps only where the backend is created using Amplify Studio or the Amplify command line interface (CLI).</p>
    pub fn backend_environment_arn(&self) -> ::std::option::Option<&str> {
        self.backend_environment_arn.as_deref()
    }
    /// <p>The backend for a <code>Branch</code> of an Amplify app. Use for a backend created from an CloudFormation stack.</p>
    /// <p>This field is available to Amplify Gen 2 apps only. When you deploy an application with Amplify Gen 2, you provision the app's backend infrastructure using Typescript code.</p>
    pub fn backend(&self) -> ::std::option::Option<&crate::types::Backend> {
        self.backend.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role to assign to a branch of an SSR app. The SSR Compute role allows the Amplify Hosting compute service to securely access specific Amazon Web Services resources based on the role's permissions. For more information about the SSR Compute role, see <a href="https://docs.aws.amazon.com/amplify/latest/userguide/amplify-SSR-compute-role.html">Adding an SSR Compute role</a> in the <i>Amplify User Guide</i>.</p>
    pub fn compute_role_arn(&self) -> ::std::option::Option<&str> {
        self.compute_role_arn.as_deref()
    }
}
impl ::std::fmt::Debug for CreateBranchInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateBranchInput");
        formatter.field("app_id", &self.app_id);
        formatter.field("branch_name", &self.branch_name);
        formatter.field("description", &self.description);
        formatter.field("stage", &self.stage);
        formatter.field("framework", &self.framework);
        formatter.field("enable_notification", &self.enable_notification);
        formatter.field("enable_auto_build", &self.enable_auto_build);
        formatter.field("enable_skew_protection", &self.enable_skew_protection);
        formatter.field("environment_variables", &self.environment_variables);
        formatter.field("basic_auth_credentials", &"*** Sensitive Data Redacted ***");
        formatter.field("enable_basic_auth", &self.enable_basic_auth);
        formatter.field("enable_performance_mode", &self.enable_performance_mode);
        formatter.field("tags", &self.tags);
        formatter.field("build_spec", &"*** Sensitive Data Redacted ***");
        formatter.field("ttl", &self.ttl);
        formatter.field("display_name", &self.display_name);
        formatter.field("enable_pull_request_preview", &self.enable_pull_request_preview);
        formatter.field("pull_request_environment_name", &self.pull_request_environment_name);
        formatter.field("backend_environment_arn", &self.backend_environment_arn);
        formatter.field("backend", &self.backend);
        formatter.field("compute_role_arn", &self.compute_role_arn);
        formatter.finish()
    }
}
impl CreateBranchInput {
    /// Creates a new builder-style object to manufacture [`CreateBranchInput`](crate::operation::create_branch::CreateBranchInput).
    pub fn builder() -> crate::operation::create_branch::builders::CreateBranchInputBuilder {
        crate::operation::create_branch::builders::CreateBranchInputBuilder::default()
    }
}

/// A builder for [`CreateBranchInput`](crate::operation::create_branch::CreateBranchInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CreateBranchInputBuilder {
    pub(crate) app_id: ::std::option::Option<::std::string::String>,
    pub(crate) branch_name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) stage: ::std::option::Option<crate::types::Stage>,
    pub(crate) framework: ::std::option::Option<::std::string::String>,
    pub(crate) enable_notification: ::std::option::Option<bool>,
    pub(crate) enable_auto_build: ::std::option::Option<bool>,
    pub(crate) enable_skew_protection: ::std::option::Option<bool>,
    pub(crate) environment_variables: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) basic_auth_credentials: ::std::option::Option<::std::string::String>,
    pub(crate) enable_basic_auth: ::std::option::Option<bool>,
    pub(crate) enable_performance_mode: ::std::option::Option<bool>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) build_spec: ::std::option::Option<::std::string::String>,
    pub(crate) ttl: ::std::option::Option<::std::string::String>,
    pub(crate) display_name: ::std::option::Option<::std::string::String>,
    pub(crate) enable_pull_request_preview: ::std::option::Option<bool>,
    pub(crate) pull_request_environment_name: ::std::option::Option<::std::string::String>,
    pub(crate) backend_environment_arn: ::std::option::Option<::std::string::String>,
    pub(crate) backend: ::std::option::Option<crate::types::Backend>,
    pub(crate) compute_role_arn: ::std::option::Option<::std::string::String>,
}
impl CreateBranchInputBuilder {
    /// <p>The unique ID for an Amplify app.</p>
    /// This field is required.
    pub fn app_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID for an Amplify app.</p>
    pub fn set_app_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_id = input;
        self
    }
    /// <p>The unique ID for an Amplify app.</p>
    pub fn get_app_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_id
    }
    /// <p>The name for the branch.</p>
    /// This field is required.
    pub fn branch_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.branch_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name for the branch.</p>
    pub fn set_branch_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.branch_name = input;
        self
    }
    /// <p>The name for the branch.</p>
    pub fn get_branch_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.branch_name
    }
    /// <p>The description for the branch.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description for the branch.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description for the branch.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>Describes the current stage for the branch.</p>
    pub fn stage(mut self, input: crate::types::Stage) -> Self {
        self.stage = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the current stage for the branch.</p>
    pub fn set_stage(mut self, input: ::std::option::Option<crate::types::Stage>) -> Self {
        self.stage = input;
        self
    }
    /// <p>Describes the current stage for the branch.</p>
    pub fn get_stage(&self) -> &::std::option::Option<crate::types::Stage> {
        &self.stage
    }
    /// <p>The framework for the branch.</p>
    pub fn framework(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.framework = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The framework for the branch.</p>
    pub fn set_framework(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.framework = input;
        self
    }
    /// <p>The framework for the branch.</p>
    pub fn get_framework(&self) -> &::std::option::Option<::std::string::String> {
        &self.framework
    }
    /// <p>Enables notifications for the branch.</p>
    pub fn enable_notification(mut self, input: bool) -> Self {
        self.enable_notification = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables notifications for the branch.</p>
    pub fn set_enable_notification(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enable_notification = input;
        self
    }
    /// <p>Enables notifications for the branch.</p>
    pub fn get_enable_notification(&self) -> &::std::option::Option<bool> {
        &self.enable_notification
    }
    /// <p>Enables auto building for the branch.</p>
    pub fn enable_auto_build(mut self, input: bool) -> Self {
        self.enable_auto_build = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables auto building for the branch.</p>
    pub fn set_enable_auto_build(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enable_auto_build = input;
        self
    }
    /// <p>Enables auto building for the branch.</p>
    pub fn get_enable_auto_build(&self) -> &::std::option::Option<bool> {
        &self.enable_auto_build
    }
    /// <p>Specifies whether the skew protection feature is enabled for the branch.</p>
    /// <p>Deployment skew protection is available to Amplify applications to eliminate version skew issues between client and servers in web applications. When you apply skew protection to a branch, you can ensure that your clients always interact with the correct version of server-side assets, regardless of when a deployment occurs. For more information about skew protection, see <a href="https://docs.aws.amazon.com/amplify/latest/userguide/skew-protection.html">Skew protection for Amplify deployments</a> in the <i>Amplify User Guide</i>.</p>
    pub fn enable_skew_protection(mut self, input: bool) -> Self {
        self.enable_skew_protection = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the skew protection feature is enabled for the branch.</p>
    /// <p>Deployment skew protection is available to Amplify applications to eliminate version skew issues between client and servers in web applications. When you apply skew protection to a branch, you can ensure that your clients always interact with the correct version of server-side assets, regardless of when a deployment occurs. For more information about skew protection, see <a href="https://docs.aws.amazon.com/amplify/latest/userguide/skew-protection.html">Skew protection for Amplify deployments</a> in the <i>Amplify User Guide</i>.</p>
    pub fn set_enable_skew_protection(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enable_skew_protection = input;
        self
    }
    /// <p>Specifies whether the skew protection feature is enabled for the branch.</p>
    /// <p>Deployment skew protection is available to Amplify applications to eliminate version skew issues between client and servers in web applications. When you apply skew protection to a branch, you can ensure that your clients always interact with the correct version of server-side assets, regardless of when a deployment occurs. For more information about skew protection, see <a href="https://docs.aws.amazon.com/amplify/latest/userguide/skew-protection.html">Skew protection for Amplify deployments</a> in the <i>Amplify User Guide</i>.</p>
    pub fn get_enable_skew_protection(&self) -> &::std::option::Option<bool> {
        &self.enable_skew_protection
    }
    /// Adds a key-value pair to `environment_variables`.
    ///
    /// To override the contents of this collection use [`set_environment_variables`](Self::set_environment_variables).
    ///
    /// <p>The environment variables for the branch.</p>
    pub fn environment_variables(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.environment_variables.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.environment_variables = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The environment variables for the branch.</p>
    pub fn set_environment_variables(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.environment_variables = input;
        self
    }
    /// <p>The environment variables for the branch.</p>
    pub fn get_environment_variables(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.environment_variables
    }
    /// <p>The basic authorization credentials for the branch. You must base64-encode the authorization credentials and provide them in the format <code>user:password</code>.</p>
    pub fn basic_auth_credentials(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.basic_auth_credentials = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The basic authorization credentials for the branch. You must base64-encode the authorization credentials and provide them in the format <code>user:password</code>.</p>
    pub fn set_basic_auth_credentials(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.basic_auth_credentials = input;
        self
    }
    /// <p>The basic authorization credentials for the branch. You must base64-encode the authorization credentials and provide them in the format <code>user:password</code>.</p>
    pub fn get_basic_auth_credentials(&self) -> &::std::option::Option<::std::string::String> {
        &self.basic_auth_credentials
    }
    /// <p>Enables basic authorization for the branch.</p>
    pub fn enable_basic_auth(mut self, input: bool) -> Self {
        self.enable_basic_auth = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables basic authorization for the branch.</p>
    pub fn set_enable_basic_auth(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enable_basic_auth = input;
        self
    }
    /// <p>Enables basic authorization for the branch.</p>
    pub fn get_enable_basic_auth(&self) -> &::std::option::Option<bool> {
        &self.enable_basic_auth
    }
    /// <p>Enables performance mode for the branch.</p>
    /// <p>Performance mode optimizes for faster hosting performance by keeping content cached at the edge for a longer interval. When performance mode is enabled, hosting configuration or code changes can take up to 10 minutes to roll out.</p>
    pub fn enable_performance_mode(mut self, input: bool) -> Self {
        self.enable_performance_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables performance mode for the branch.</p>
    /// <p>Performance mode optimizes for faster hosting performance by keeping content cached at the edge for a longer interval. When performance mode is enabled, hosting configuration or code changes can take up to 10 minutes to roll out.</p>
    pub fn set_enable_performance_mode(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enable_performance_mode = input;
        self
    }
    /// <p>Enables performance mode for the branch.</p>
    /// <p>Performance mode optimizes for faster hosting performance by keeping content cached at the edge for a longer interval. When performance mode is enabled, hosting configuration or code changes can take up to 10 minutes to roll out.</p>
    pub fn get_enable_performance_mode(&self) -> &::std::option::Option<bool> {
        &self.enable_performance_mode
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tag for the branch.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tag for the branch.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tag for the branch.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>The build specification (build spec) for the branch.</p>
    pub fn build_spec(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.build_spec = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The build specification (build spec) for the branch.</p>
    pub fn set_build_spec(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.build_spec = input;
        self
    }
    /// <p>The build specification (build spec) for the branch.</p>
    pub fn get_build_spec(&self) -> &::std::option::Option<::std::string::String> {
        &self.build_spec
    }
    /// <p>The content Time To Live (TTL) for the website in seconds.</p>
    pub fn ttl(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ttl = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The content Time To Live (TTL) for the website in seconds.</p>
    pub fn set_ttl(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ttl = input;
        self
    }
    /// <p>The content Time To Live (TTL) for the website in seconds.</p>
    pub fn get_ttl(&self) -> &::std::option::Option<::std::string::String> {
        &self.ttl
    }
    /// <p>The display name for a branch. This is used as the default domain prefix.</p>
    pub fn display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The display name for a branch. This is used as the default domain prefix.</p>
    pub fn set_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.display_name = input;
        self
    }
    /// <p>The display name for a branch. This is used as the default domain prefix.</p>
    pub fn get_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.display_name
    }
    /// <p>Enables pull request previews for this branch.</p>
    pub fn enable_pull_request_preview(mut self, input: bool) -> Self {
        self.enable_pull_request_preview = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables pull request previews for this branch.</p>
    pub fn set_enable_pull_request_preview(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enable_pull_request_preview = input;
        self
    }
    /// <p>Enables pull request previews for this branch.</p>
    pub fn get_enable_pull_request_preview(&self) -> &::std::option::Option<bool> {
        &self.enable_pull_request_preview
    }
    /// <p>The Amplify environment name for the pull request.</p>
    pub fn pull_request_environment_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pull_request_environment_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amplify environment name for the pull request.</p>
    pub fn set_pull_request_environment_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pull_request_environment_name = input;
        self
    }
    /// <p>The Amplify environment name for the pull request.</p>
    pub fn get_pull_request_environment_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.pull_request_environment_name
    }
    /// <p>The Amazon Resource Name (ARN) for a backend environment that is part of a Gen 1 Amplify app.</p>
    /// <p>This field is available to Amplify Gen 1 apps only where the backend is created using Amplify Studio or the Amplify command line interface (CLI).</p>
    pub fn backend_environment_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.backend_environment_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for a backend environment that is part of a Gen 1 Amplify app.</p>
    /// <p>This field is available to Amplify Gen 1 apps only where the backend is created using Amplify Studio or the Amplify command line interface (CLI).</p>
    pub fn set_backend_environment_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.backend_environment_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for a backend environment that is part of a Gen 1 Amplify app.</p>
    /// <p>This field is available to Amplify Gen 1 apps only where the backend is created using Amplify Studio or the Amplify command line interface (CLI).</p>
    pub fn get_backend_environment_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.backend_environment_arn
    }
    /// <p>The backend for a <code>Branch</code> of an Amplify app. Use for a backend created from an CloudFormation stack.</p>
    /// <p>This field is available to Amplify Gen 2 apps only. When you deploy an application with Amplify Gen 2, you provision the app's backend infrastructure using Typescript code.</p>
    pub fn backend(mut self, input: crate::types::Backend) -> Self {
        self.backend = ::std::option::Option::Some(input);
        self
    }
    /// <p>The backend for a <code>Branch</code> of an Amplify app. Use for a backend created from an CloudFormation stack.</p>
    /// <p>This field is available to Amplify Gen 2 apps only. When you deploy an application with Amplify Gen 2, you provision the app's backend infrastructure using Typescript code.</p>
    pub fn set_backend(mut self, input: ::std::option::Option<crate::types::Backend>) -> Self {
        self.backend = input;
        self
    }
    /// <p>The backend for a <code>Branch</code> of an Amplify app. Use for a backend created from an CloudFormation stack.</p>
    /// <p>This field is available to Amplify Gen 2 apps only. When you deploy an application with Amplify Gen 2, you provision the app's backend infrastructure using Typescript code.</p>
    pub fn get_backend(&self) -> &::std::option::Option<crate::types::Backend> {
        &self.backend
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role to assign to a branch of an SSR app. The SSR Compute role allows the Amplify Hosting compute service to securely access specific Amazon Web Services resources based on the role's permissions. For more information about the SSR Compute role, see <a href="https://docs.aws.amazon.com/amplify/latest/userguide/amplify-SSR-compute-role.html">Adding an SSR Compute role</a> in the <i>Amplify User Guide</i>.</p>
    pub fn compute_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.compute_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role to assign to a branch of an SSR app. The SSR Compute role allows the Amplify Hosting compute service to securely access specific Amazon Web Services resources based on the role's permissions. For more information about the SSR Compute role, see <a href="https://docs.aws.amazon.com/amplify/latest/userguide/amplify-SSR-compute-role.html">Adding an SSR Compute role</a> in the <i>Amplify User Guide</i>.</p>
    pub fn set_compute_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.compute_role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role to assign to a branch of an SSR app. The SSR Compute role allows the Amplify Hosting compute service to securely access specific Amazon Web Services resources based on the role's permissions. For more information about the SSR Compute role, see <a href="https://docs.aws.amazon.com/amplify/latest/userguide/amplify-SSR-compute-role.html">Adding an SSR Compute role</a> in the <i>Amplify User Guide</i>.</p>
    pub fn get_compute_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.compute_role_arn
    }
    /// Consumes the builder and constructs a [`CreateBranchInput`](crate::operation::create_branch::CreateBranchInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_branch::CreateBranchInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_branch::CreateBranchInput {
            app_id: self.app_id,
            branch_name: self.branch_name,
            description: self.description,
            stage: self.stage,
            framework: self.framework,
            enable_notification: self.enable_notification,
            enable_auto_build: self.enable_auto_build,
            enable_skew_protection: self.enable_skew_protection,
            environment_variables: self.environment_variables,
            basic_auth_credentials: self.basic_auth_credentials,
            enable_basic_auth: self.enable_basic_auth,
            enable_performance_mode: self.enable_performance_mode,
            tags: self.tags,
            build_spec: self.build_spec,
            ttl: self.ttl,
            display_name: self.display_name,
            enable_pull_request_preview: self.enable_pull_request_preview,
            pull_request_environment_name: self.pull_request_environment_name,
            backend_environment_arn: self.backend_environment_arn,
            backend: self.backend,
            compute_role_arn: self.compute_role_arn,
        })
    }
}
impl ::std::fmt::Debug for CreateBranchInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateBranchInputBuilder");
        formatter.field("app_id", &self.app_id);
        formatter.field("branch_name", &self.branch_name);
        formatter.field("description", &self.description);
        formatter.field("stage", &self.stage);
        formatter.field("framework", &self.framework);
        formatter.field("enable_notification", &self.enable_notification);
        formatter.field("enable_auto_build", &self.enable_auto_build);
        formatter.field("enable_skew_protection", &self.enable_skew_protection);
        formatter.field("environment_variables", &self.environment_variables);
        formatter.field("basic_auth_credentials", &"*** Sensitive Data Redacted ***");
        formatter.field("enable_basic_auth", &self.enable_basic_auth);
        formatter.field("enable_performance_mode", &self.enable_performance_mode);
        formatter.field("tags", &self.tags);
        formatter.field("build_spec", &"*** Sensitive Data Redacted ***");
        formatter.field("ttl", &self.ttl);
        formatter.field("display_name", &self.display_name);
        formatter.field("enable_pull_request_preview", &self.enable_pull_request_preview);
        formatter.field("pull_request_environment_name", &self.pull_request_environment_name);
        formatter.field("backend_environment_arn", &self.backend_environment_arn);
        formatter.field("backend", &self.backend);
        formatter.field("compute_role_arn", &self.compute_role_arn);
        formatter.finish()
    }
}
