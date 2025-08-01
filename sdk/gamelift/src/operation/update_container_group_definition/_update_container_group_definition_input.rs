// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateContainerGroupDefinitionInput {
    /// <p>A descriptive identifier for the container group definition. The name value must be unique in an Amazon Web Services Region.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>An updated definition for the game server container in this group. Define a game server container only when the container group type is <code>GAME_SERVER</code>. You can pass in your container definitions as a JSON file.</p>
    pub game_server_container_definition: ::std::option::Option<crate::types::GameServerContainerDefinitionInput>,
    /// <p>One or more definitions for support containers in this group. You can define a support container in any type of container group. You can pass in your container definitions as a JSON file.</p>
    pub support_container_definitions: ::std::option::Option<::std::vec::Vec<crate::types::SupportContainerDefinitionInput>>,
    /// <p>The maximum amount of memory (in MiB) to allocate to the container group. All containers in the group share this memory. If you specify memory limits for an individual container, the total value must be greater than any individual container's memory limit.</p>
    pub total_memory_limit_mebibytes: ::std::option::Option<i32>,
    /// <p>The maximum amount of vCPU units to allocate to the container group (1 vCPU is equal to 1024 CPU units). All containers in the group share this memory. If you specify vCPU limits for individual containers, the total value must be equal to or greater than the sum of the CPU limits for all containers in the group.</p>
    pub total_vcpu_limit: ::std::option::Option<f64>,
    /// <p>A description for this update to the container group definition.</p>
    pub version_description: ::std::option::Option<::std::string::String>,
    /// <p>The container group definition version to update. The new version starts with values from the source version, and then updates values included in this request.</p>
    pub source_version_number: ::std::option::Option<i32>,
    /// <p>The platform that all containers in the group use. Containers in a group must run on the same operating system.</p><note>
    /// <p>Amazon Linux 2 (AL2) will reach end of support on 6/30/2025. See more details in the <a href="http://aws.amazon.com/amazon-linux-2/faqs/">Amazon Linux 2 FAQs</a>. For game servers that are hosted on AL2 and use server SDK version 4.x for Amazon GameLift Servers, first update the game server build to server SDK 5.x, and then deploy to AL2023 instances. See <a href="https://docs.aws.amazon.com/gamelift/latest/developerguide/reference-serversdk5-migration.html"> Migrate to server SDK version 5.</a></p>
    /// </note>
    pub operating_system: ::std::option::Option<crate::types::ContainerOperatingSystem>,
}
impl UpdateContainerGroupDefinitionInput {
    /// <p>A descriptive identifier for the container group definition. The name value must be unique in an Amazon Web Services Region.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>An updated definition for the game server container in this group. Define a game server container only when the container group type is <code>GAME_SERVER</code>. You can pass in your container definitions as a JSON file.</p>
    pub fn game_server_container_definition(&self) -> ::std::option::Option<&crate::types::GameServerContainerDefinitionInput> {
        self.game_server_container_definition.as_ref()
    }
    /// <p>One or more definitions for support containers in this group. You can define a support container in any type of container group. You can pass in your container definitions as a JSON file.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.support_container_definitions.is_none()`.
    pub fn support_container_definitions(&self) -> &[crate::types::SupportContainerDefinitionInput] {
        self.support_container_definitions.as_deref().unwrap_or_default()
    }
    /// <p>The maximum amount of memory (in MiB) to allocate to the container group. All containers in the group share this memory. If you specify memory limits for an individual container, the total value must be greater than any individual container's memory limit.</p>
    pub fn total_memory_limit_mebibytes(&self) -> ::std::option::Option<i32> {
        self.total_memory_limit_mebibytes
    }
    /// <p>The maximum amount of vCPU units to allocate to the container group (1 vCPU is equal to 1024 CPU units). All containers in the group share this memory. If you specify vCPU limits for individual containers, the total value must be equal to or greater than the sum of the CPU limits for all containers in the group.</p>
    pub fn total_vcpu_limit(&self) -> ::std::option::Option<f64> {
        self.total_vcpu_limit
    }
    /// <p>A description for this update to the container group definition.</p>
    pub fn version_description(&self) -> ::std::option::Option<&str> {
        self.version_description.as_deref()
    }
    /// <p>The container group definition version to update. The new version starts with values from the source version, and then updates values included in this request.</p>
    pub fn source_version_number(&self) -> ::std::option::Option<i32> {
        self.source_version_number
    }
    /// <p>The platform that all containers in the group use. Containers in a group must run on the same operating system.</p><note>
    /// <p>Amazon Linux 2 (AL2) will reach end of support on 6/30/2025. See more details in the <a href="http://aws.amazon.com/amazon-linux-2/faqs/">Amazon Linux 2 FAQs</a>. For game servers that are hosted on AL2 and use server SDK version 4.x for Amazon GameLift Servers, first update the game server build to server SDK 5.x, and then deploy to AL2023 instances. See <a href="https://docs.aws.amazon.com/gamelift/latest/developerguide/reference-serversdk5-migration.html"> Migrate to server SDK version 5.</a></p>
    /// </note>
    pub fn operating_system(&self) -> ::std::option::Option<&crate::types::ContainerOperatingSystem> {
        self.operating_system.as_ref()
    }
}
impl UpdateContainerGroupDefinitionInput {
    /// Creates a new builder-style object to manufacture [`UpdateContainerGroupDefinitionInput`](crate::operation::update_container_group_definition::UpdateContainerGroupDefinitionInput).
    pub fn builder() -> crate::operation::update_container_group_definition::builders::UpdateContainerGroupDefinitionInputBuilder {
        crate::operation::update_container_group_definition::builders::UpdateContainerGroupDefinitionInputBuilder::default()
    }
}

/// A builder for [`UpdateContainerGroupDefinitionInput`](crate::operation::update_container_group_definition::UpdateContainerGroupDefinitionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateContainerGroupDefinitionInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) game_server_container_definition: ::std::option::Option<crate::types::GameServerContainerDefinitionInput>,
    pub(crate) support_container_definitions: ::std::option::Option<::std::vec::Vec<crate::types::SupportContainerDefinitionInput>>,
    pub(crate) total_memory_limit_mebibytes: ::std::option::Option<i32>,
    pub(crate) total_vcpu_limit: ::std::option::Option<f64>,
    pub(crate) version_description: ::std::option::Option<::std::string::String>,
    pub(crate) source_version_number: ::std::option::Option<i32>,
    pub(crate) operating_system: ::std::option::Option<crate::types::ContainerOperatingSystem>,
}
impl UpdateContainerGroupDefinitionInputBuilder {
    /// <p>A descriptive identifier for the container group definition. The name value must be unique in an Amazon Web Services Region.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A descriptive identifier for the container group definition. The name value must be unique in an Amazon Web Services Region.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>A descriptive identifier for the container group definition. The name value must be unique in an Amazon Web Services Region.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>An updated definition for the game server container in this group. Define a game server container only when the container group type is <code>GAME_SERVER</code>. You can pass in your container definitions as a JSON file.</p>
    pub fn game_server_container_definition(mut self, input: crate::types::GameServerContainerDefinitionInput) -> Self {
        self.game_server_container_definition = ::std::option::Option::Some(input);
        self
    }
    /// <p>An updated definition for the game server container in this group. Define a game server container only when the container group type is <code>GAME_SERVER</code>. You can pass in your container definitions as a JSON file.</p>
    pub fn set_game_server_container_definition(mut self, input: ::std::option::Option<crate::types::GameServerContainerDefinitionInput>) -> Self {
        self.game_server_container_definition = input;
        self
    }
    /// <p>An updated definition for the game server container in this group. Define a game server container only when the container group type is <code>GAME_SERVER</code>. You can pass in your container definitions as a JSON file.</p>
    pub fn get_game_server_container_definition(&self) -> &::std::option::Option<crate::types::GameServerContainerDefinitionInput> {
        &self.game_server_container_definition
    }
    /// Appends an item to `support_container_definitions`.
    ///
    /// To override the contents of this collection use [`set_support_container_definitions`](Self::set_support_container_definitions).
    ///
    /// <p>One or more definitions for support containers in this group. You can define a support container in any type of container group. You can pass in your container definitions as a JSON file.</p>
    pub fn support_container_definitions(mut self, input: crate::types::SupportContainerDefinitionInput) -> Self {
        let mut v = self.support_container_definitions.unwrap_or_default();
        v.push(input);
        self.support_container_definitions = ::std::option::Option::Some(v);
        self
    }
    /// <p>One or more definitions for support containers in this group. You can define a support container in any type of container group. You can pass in your container definitions as a JSON file.</p>
    pub fn set_support_container_definitions(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::SupportContainerDefinitionInput>>,
    ) -> Self {
        self.support_container_definitions = input;
        self
    }
    /// <p>One or more definitions for support containers in this group. You can define a support container in any type of container group. You can pass in your container definitions as a JSON file.</p>
    pub fn get_support_container_definitions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SupportContainerDefinitionInput>> {
        &self.support_container_definitions
    }
    /// <p>The maximum amount of memory (in MiB) to allocate to the container group. All containers in the group share this memory. If you specify memory limits for an individual container, the total value must be greater than any individual container's memory limit.</p>
    pub fn total_memory_limit_mebibytes(mut self, input: i32) -> Self {
        self.total_memory_limit_mebibytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum amount of memory (in MiB) to allocate to the container group. All containers in the group share this memory. If you specify memory limits for an individual container, the total value must be greater than any individual container's memory limit.</p>
    pub fn set_total_memory_limit_mebibytes(mut self, input: ::std::option::Option<i32>) -> Self {
        self.total_memory_limit_mebibytes = input;
        self
    }
    /// <p>The maximum amount of memory (in MiB) to allocate to the container group. All containers in the group share this memory. If you specify memory limits for an individual container, the total value must be greater than any individual container's memory limit.</p>
    pub fn get_total_memory_limit_mebibytes(&self) -> &::std::option::Option<i32> {
        &self.total_memory_limit_mebibytes
    }
    /// <p>The maximum amount of vCPU units to allocate to the container group (1 vCPU is equal to 1024 CPU units). All containers in the group share this memory. If you specify vCPU limits for individual containers, the total value must be equal to or greater than the sum of the CPU limits for all containers in the group.</p>
    pub fn total_vcpu_limit(mut self, input: f64) -> Self {
        self.total_vcpu_limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum amount of vCPU units to allocate to the container group (1 vCPU is equal to 1024 CPU units). All containers in the group share this memory. If you specify vCPU limits for individual containers, the total value must be equal to or greater than the sum of the CPU limits for all containers in the group.</p>
    pub fn set_total_vcpu_limit(mut self, input: ::std::option::Option<f64>) -> Self {
        self.total_vcpu_limit = input;
        self
    }
    /// <p>The maximum amount of vCPU units to allocate to the container group (1 vCPU is equal to 1024 CPU units). All containers in the group share this memory. If you specify vCPU limits for individual containers, the total value must be equal to or greater than the sum of the CPU limits for all containers in the group.</p>
    pub fn get_total_vcpu_limit(&self) -> &::std::option::Option<f64> {
        &self.total_vcpu_limit
    }
    /// <p>A description for this update to the container group definition.</p>
    pub fn version_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description for this update to the container group definition.</p>
    pub fn set_version_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version_description = input;
        self
    }
    /// <p>A description for this update to the container group definition.</p>
    pub fn get_version_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.version_description
    }
    /// <p>The container group definition version to update. The new version starts with values from the source version, and then updates values included in this request.</p>
    pub fn source_version_number(mut self, input: i32) -> Self {
        self.source_version_number = ::std::option::Option::Some(input);
        self
    }
    /// <p>The container group definition version to update. The new version starts with values from the source version, and then updates values included in this request.</p>
    pub fn set_source_version_number(mut self, input: ::std::option::Option<i32>) -> Self {
        self.source_version_number = input;
        self
    }
    /// <p>The container group definition version to update. The new version starts with values from the source version, and then updates values included in this request.</p>
    pub fn get_source_version_number(&self) -> &::std::option::Option<i32> {
        &self.source_version_number
    }
    /// <p>The platform that all containers in the group use. Containers in a group must run on the same operating system.</p><note>
    /// <p>Amazon Linux 2 (AL2) will reach end of support on 6/30/2025. See more details in the <a href="http://aws.amazon.com/amazon-linux-2/faqs/">Amazon Linux 2 FAQs</a>. For game servers that are hosted on AL2 and use server SDK version 4.x for Amazon GameLift Servers, first update the game server build to server SDK 5.x, and then deploy to AL2023 instances. See <a href="https://docs.aws.amazon.com/gamelift/latest/developerguide/reference-serversdk5-migration.html"> Migrate to server SDK version 5.</a></p>
    /// </note>
    pub fn operating_system(mut self, input: crate::types::ContainerOperatingSystem) -> Self {
        self.operating_system = ::std::option::Option::Some(input);
        self
    }
    /// <p>The platform that all containers in the group use. Containers in a group must run on the same operating system.</p><note>
    /// <p>Amazon Linux 2 (AL2) will reach end of support on 6/30/2025. See more details in the <a href="http://aws.amazon.com/amazon-linux-2/faqs/">Amazon Linux 2 FAQs</a>. For game servers that are hosted on AL2 and use server SDK version 4.x for Amazon GameLift Servers, first update the game server build to server SDK 5.x, and then deploy to AL2023 instances. See <a href="https://docs.aws.amazon.com/gamelift/latest/developerguide/reference-serversdk5-migration.html"> Migrate to server SDK version 5.</a></p>
    /// </note>
    pub fn set_operating_system(mut self, input: ::std::option::Option<crate::types::ContainerOperatingSystem>) -> Self {
        self.operating_system = input;
        self
    }
    /// <p>The platform that all containers in the group use. Containers in a group must run on the same operating system.</p><note>
    /// <p>Amazon Linux 2 (AL2) will reach end of support on 6/30/2025. See more details in the <a href="http://aws.amazon.com/amazon-linux-2/faqs/">Amazon Linux 2 FAQs</a>. For game servers that are hosted on AL2 and use server SDK version 4.x for Amazon GameLift Servers, first update the game server build to server SDK 5.x, and then deploy to AL2023 instances. See <a href="https://docs.aws.amazon.com/gamelift/latest/developerguide/reference-serversdk5-migration.html"> Migrate to server SDK version 5.</a></p>
    /// </note>
    pub fn get_operating_system(&self) -> &::std::option::Option<crate::types::ContainerOperatingSystem> {
        &self.operating_system
    }
    /// Consumes the builder and constructs a [`UpdateContainerGroupDefinitionInput`](crate::operation::update_container_group_definition::UpdateContainerGroupDefinitionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_container_group_definition::UpdateContainerGroupDefinitionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_container_group_definition::UpdateContainerGroupDefinitionInput {
            name: self.name,
            game_server_container_definition: self.game_server_container_definition,
            support_container_definitions: self.support_container_definitions,
            total_memory_limit_mebibytes: self.total_memory_limit_mebibytes,
            total_vcpu_limit: self.total_vcpu_limit,
            version_description: self.version_description,
            source_version_number: self.source_version_number,
            operating_system: self.operating_system,
        })
    }
}
