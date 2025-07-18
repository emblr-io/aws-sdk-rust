// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateRobotApplicationOutput {
    /// <p>The Amazon Resource Name (ARN) of the robot application.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the robot application.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The version of the robot application.</p>
    pub version: ::std::option::Option<::std::string::String>,
    /// <p>The sources of the robot application.</p>
    pub sources: ::std::option::Option<::std::vec::Vec<crate::types::Source>>,
    /// <p>The robot software suite used by the robot application.</p>
    pub robot_software_suite: ::std::option::Option<crate::types::RobotSoftwareSuite>,
    /// <p>The time, in milliseconds since the epoch, when the robot application was last updated.</p>
    pub last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The revision id of the robot application.</p>
    pub revision_id: ::std::option::Option<::std::string::String>,
    /// <p>The list of all tags added to the robot application.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>An object that contains the Docker image URI used to a create your robot application.</p>
    pub environment: ::std::option::Option<crate::types::Environment>,
    _request_id: Option<String>,
}
impl CreateRobotApplicationOutput {
    /// <p>The Amazon Resource Name (ARN) of the robot application.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The name of the robot application.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The version of the robot application.</p>
    pub fn version(&self) -> ::std::option::Option<&str> {
        self.version.as_deref()
    }
    /// <p>The sources of the robot application.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.sources.is_none()`.
    pub fn sources(&self) -> &[crate::types::Source] {
        self.sources.as_deref().unwrap_or_default()
    }
    /// <p>The robot software suite used by the robot application.</p>
    pub fn robot_software_suite(&self) -> ::std::option::Option<&crate::types::RobotSoftwareSuite> {
        self.robot_software_suite.as_ref()
    }
    /// <p>The time, in milliseconds since the epoch, when the robot application was last updated.</p>
    pub fn last_updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_at.as_ref()
    }
    /// <p>The revision id of the robot application.</p>
    pub fn revision_id(&self) -> ::std::option::Option<&str> {
        self.revision_id.as_deref()
    }
    /// <p>The list of all tags added to the robot application.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>An object that contains the Docker image URI used to a create your robot application.</p>
    pub fn environment(&self) -> ::std::option::Option<&crate::types::Environment> {
        self.environment.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateRobotApplicationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateRobotApplicationOutput {
    /// Creates a new builder-style object to manufacture [`CreateRobotApplicationOutput`](crate::operation::create_robot_application::CreateRobotApplicationOutput).
    pub fn builder() -> crate::operation::create_robot_application::builders::CreateRobotApplicationOutputBuilder {
        crate::operation::create_robot_application::builders::CreateRobotApplicationOutputBuilder::default()
    }
}

/// A builder for [`CreateRobotApplicationOutput`](crate::operation::create_robot_application::CreateRobotApplicationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateRobotApplicationOutputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) version: ::std::option::Option<::std::string::String>,
    pub(crate) sources: ::std::option::Option<::std::vec::Vec<crate::types::Source>>,
    pub(crate) robot_software_suite: ::std::option::Option<crate::types::RobotSoftwareSuite>,
    pub(crate) last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) revision_id: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) environment: ::std::option::Option<crate::types::Environment>,
    _request_id: Option<String>,
}
impl CreateRobotApplicationOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the robot application.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the robot application.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the robot application.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The name of the robot application.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the robot application.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the robot application.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The version of the robot application.</p>
    pub fn version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the robot application.</p>
    pub fn set_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version = input;
        self
    }
    /// <p>The version of the robot application.</p>
    pub fn get_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.version
    }
    /// Appends an item to `sources`.
    ///
    /// To override the contents of this collection use [`set_sources`](Self::set_sources).
    ///
    /// <p>The sources of the robot application.</p>
    pub fn sources(mut self, input: crate::types::Source) -> Self {
        let mut v = self.sources.unwrap_or_default();
        v.push(input);
        self.sources = ::std::option::Option::Some(v);
        self
    }
    /// <p>The sources of the robot application.</p>
    pub fn set_sources(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Source>>) -> Self {
        self.sources = input;
        self
    }
    /// <p>The sources of the robot application.</p>
    pub fn get_sources(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Source>> {
        &self.sources
    }
    /// <p>The robot software suite used by the robot application.</p>
    pub fn robot_software_suite(mut self, input: crate::types::RobotSoftwareSuite) -> Self {
        self.robot_software_suite = ::std::option::Option::Some(input);
        self
    }
    /// <p>The robot software suite used by the robot application.</p>
    pub fn set_robot_software_suite(mut self, input: ::std::option::Option<crate::types::RobotSoftwareSuite>) -> Self {
        self.robot_software_suite = input;
        self
    }
    /// <p>The robot software suite used by the robot application.</p>
    pub fn get_robot_software_suite(&self) -> &::std::option::Option<crate::types::RobotSoftwareSuite> {
        &self.robot_software_suite
    }
    /// <p>The time, in milliseconds since the epoch, when the robot application was last updated.</p>
    pub fn last_updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time, in milliseconds since the epoch, when the robot application was last updated.</p>
    pub fn set_last_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_at = input;
        self
    }
    /// <p>The time, in milliseconds since the epoch, when the robot application was last updated.</p>
    pub fn get_last_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_at
    }
    /// <p>The revision id of the robot application.</p>
    pub fn revision_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.revision_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The revision id of the robot application.</p>
    pub fn set_revision_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.revision_id = input;
        self
    }
    /// <p>The revision id of the robot application.</p>
    pub fn get_revision_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.revision_id
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The list of all tags added to the robot application.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The list of all tags added to the robot application.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The list of all tags added to the robot application.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>An object that contains the Docker image URI used to a create your robot application.</p>
    pub fn environment(mut self, input: crate::types::Environment) -> Self {
        self.environment = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains the Docker image URI used to a create your robot application.</p>
    pub fn set_environment(mut self, input: ::std::option::Option<crate::types::Environment>) -> Self {
        self.environment = input;
        self
    }
    /// <p>An object that contains the Docker image URI used to a create your robot application.</p>
    pub fn get_environment(&self) -> &::std::option::Option<crate::types::Environment> {
        &self.environment
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateRobotApplicationOutput`](crate::operation::create_robot_application::CreateRobotApplicationOutput).
    pub fn build(self) -> crate::operation::create_robot_application::CreateRobotApplicationOutput {
        crate::operation::create_robot_application::CreateRobotApplicationOutput {
            arn: self.arn,
            name: self.name,
            version: self.version,
            sources: self.sources,
            robot_software_suite: self.robot_software_suite,
            last_updated_at: self.last_updated_at,
            revision_id: self.revision_id,
            tags: self.tags,
            environment: self.environment,
            _request_id: self._request_id,
        }
    }
}
