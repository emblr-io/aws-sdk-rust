// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateBuildInput {
    /// <p>A descriptive label that is associated with a build. Build names do not need to be unique. You can change this value later.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Version information that is associated with a build or script. Version strings do not need to be unique. You can change this value later.</p>
    pub version: ::std::option::Option<::std::string::String>,
    /// <p>Information indicating where your game build files are stored. Use this parameter only when creating a build with files stored in an Amazon S3 bucket that you own. The storage location must specify an Amazon S3 bucket name and key. The location must also specify a role ARN that you set up to allow Amazon GameLift Servers to access your Amazon S3 bucket. The S3 bucket and your new build must be in the same Region.</p>
    /// <p>If a <code>StorageLocation</code> is specified, the size of your file can be found in your Amazon S3 bucket. Amazon GameLift Servers will report a <code>SizeOnDisk</code> of 0.</p>
    pub storage_location: ::std::option::Option<crate::types::S3Location>,
    /// <p>The operating system that your game server binaries run on. This value determines the type of fleet resources that you use for this build. If your game build contains multiple executables, they all must run on the same operating system. You must specify a valid operating system in this request. There is no default value. You can't change a build's operating system later.</p><note>
    /// <p>Amazon Linux 2 (AL2) will reach end of support on 6/30/2025. See more details in the <a href="http://aws.amazon.com/amazon-linux-2/faqs/">Amazon Linux 2 FAQs</a>. For game servers that are hosted on AL2 and use server SDK version 4.x for Amazon GameLift Servers, first update the game server build to server SDK 5.x, and then deploy to AL2023 instances. See <a href="https://docs.aws.amazon.com/gamelift/latest/developerguide/reference-serversdk5-migration.html"> Migrate to server SDK version 5.</a></p>
    /// </note>
    pub operating_system: ::std::option::Option<crate::types::OperatingSystem>,
    /// <p>A list of labels to assign to the new build resource. Tags are developer defined key-value pairs. Tagging Amazon Web Services resources are useful for resource management, access management and cost allocation. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html"> Tagging Amazon Web Services Resources</a> in the <i>Amazon Web Services General Reference</i>. Once the resource is created, you can use <a href="https://docs.aws.amazon.com/gamelift/latest/apireference/API_TagResource.html">TagResource</a>, <a href="https://docs.aws.amazon.com/gamelift/latest/apireference/API_UntagResource.html">UntagResource</a>, and <a href="https://docs.aws.amazon.com/gamelift/latest/apireference/API_ListTagsForResource.html">ListTagsForResource</a> to add, remove, and view tags. The maximum tag limit may be lower than stated. See the Amazon Web Services General Reference for actual tagging limits.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>A server SDK version you used when integrating your game server build with Amazon GameLift Servers. For more information see <a href="https://docs.aws.amazon.com/gamelift/latest/developerguide/integration-custom-intro.html">Integrate games with custom game servers</a>. By default Amazon GameLift Servers sets this value to <code>4.0.2</code>.</p>
    pub server_sdk_version: ::std::option::Option<::std::string::String>,
}
impl CreateBuildInput {
    /// <p>A descriptive label that is associated with a build. Build names do not need to be unique. You can change this value later.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Version information that is associated with a build or script. Version strings do not need to be unique. You can change this value later.</p>
    pub fn version(&self) -> ::std::option::Option<&str> {
        self.version.as_deref()
    }
    /// <p>Information indicating where your game build files are stored. Use this parameter only when creating a build with files stored in an Amazon S3 bucket that you own. The storage location must specify an Amazon S3 bucket name and key. The location must also specify a role ARN that you set up to allow Amazon GameLift Servers to access your Amazon S3 bucket. The S3 bucket and your new build must be in the same Region.</p>
    /// <p>If a <code>StorageLocation</code> is specified, the size of your file can be found in your Amazon S3 bucket. Amazon GameLift Servers will report a <code>SizeOnDisk</code> of 0.</p>
    pub fn storage_location(&self) -> ::std::option::Option<&crate::types::S3Location> {
        self.storage_location.as_ref()
    }
    /// <p>The operating system that your game server binaries run on. This value determines the type of fleet resources that you use for this build. If your game build contains multiple executables, they all must run on the same operating system. You must specify a valid operating system in this request. There is no default value. You can't change a build's operating system later.</p><note>
    /// <p>Amazon Linux 2 (AL2) will reach end of support on 6/30/2025. See more details in the <a href="http://aws.amazon.com/amazon-linux-2/faqs/">Amazon Linux 2 FAQs</a>. For game servers that are hosted on AL2 and use server SDK version 4.x for Amazon GameLift Servers, first update the game server build to server SDK 5.x, and then deploy to AL2023 instances. See <a href="https://docs.aws.amazon.com/gamelift/latest/developerguide/reference-serversdk5-migration.html"> Migrate to server SDK version 5.</a></p>
    /// </note>
    pub fn operating_system(&self) -> ::std::option::Option<&crate::types::OperatingSystem> {
        self.operating_system.as_ref()
    }
    /// <p>A list of labels to assign to the new build resource. Tags are developer defined key-value pairs. Tagging Amazon Web Services resources are useful for resource management, access management and cost allocation. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html"> Tagging Amazon Web Services Resources</a> in the <i>Amazon Web Services General Reference</i>. Once the resource is created, you can use <a href="https://docs.aws.amazon.com/gamelift/latest/apireference/API_TagResource.html">TagResource</a>, <a href="https://docs.aws.amazon.com/gamelift/latest/apireference/API_UntagResource.html">UntagResource</a>, and <a href="https://docs.aws.amazon.com/gamelift/latest/apireference/API_ListTagsForResource.html">ListTagsForResource</a> to add, remove, and view tags. The maximum tag limit may be lower than stated. See the Amazon Web Services General Reference for actual tagging limits.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>A server SDK version you used when integrating your game server build with Amazon GameLift Servers. For more information see <a href="https://docs.aws.amazon.com/gamelift/latest/developerguide/integration-custom-intro.html">Integrate games with custom game servers</a>. By default Amazon GameLift Servers sets this value to <code>4.0.2</code>.</p>
    pub fn server_sdk_version(&self) -> ::std::option::Option<&str> {
        self.server_sdk_version.as_deref()
    }
}
impl CreateBuildInput {
    /// Creates a new builder-style object to manufacture [`CreateBuildInput`](crate::operation::create_build::CreateBuildInput).
    pub fn builder() -> crate::operation::create_build::builders::CreateBuildInputBuilder {
        crate::operation::create_build::builders::CreateBuildInputBuilder::default()
    }
}

/// A builder for [`CreateBuildInput`](crate::operation::create_build::CreateBuildInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateBuildInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) version: ::std::option::Option<::std::string::String>,
    pub(crate) storage_location: ::std::option::Option<crate::types::S3Location>,
    pub(crate) operating_system: ::std::option::Option<crate::types::OperatingSystem>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) server_sdk_version: ::std::option::Option<::std::string::String>,
}
impl CreateBuildInputBuilder {
    /// <p>A descriptive label that is associated with a build. Build names do not need to be unique. You can change this value later.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A descriptive label that is associated with a build. Build names do not need to be unique. You can change this value later.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>A descriptive label that is associated with a build. Build names do not need to be unique. You can change this value later.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Version information that is associated with a build or script. Version strings do not need to be unique. You can change this value later.</p>
    pub fn version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Version information that is associated with a build or script. Version strings do not need to be unique. You can change this value later.</p>
    pub fn set_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version = input;
        self
    }
    /// <p>Version information that is associated with a build or script. Version strings do not need to be unique. You can change this value later.</p>
    pub fn get_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.version
    }
    /// <p>Information indicating where your game build files are stored. Use this parameter only when creating a build with files stored in an Amazon S3 bucket that you own. The storage location must specify an Amazon S3 bucket name and key. The location must also specify a role ARN that you set up to allow Amazon GameLift Servers to access your Amazon S3 bucket. The S3 bucket and your new build must be in the same Region.</p>
    /// <p>If a <code>StorageLocation</code> is specified, the size of your file can be found in your Amazon S3 bucket. Amazon GameLift Servers will report a <code>SizeOnDisk</code> of 0.</p>
    pub fn storage_location(mut self, input: crate::types::S3Location) -> Self {
        self.storage_location = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information indicating where your game build files are stored. Use this parameter only when creating a build with files stored in an Amazon S3 bucket that you own. The storage location must specify an Amazon S3 bucket name and key. The location must also specify a role ARN that you set up to allow Amazon GameLift Servers to access your Amazon S3 bucket. The S3 bucket and your new build must be in the same Region.</p>
    /// <p>If a <code>StorageLocation</code> is specified, the size of your file can be found in your Amazon S3 bucket. Amazon GameLift Servers will report a <code>SizeOnDisk</code> of 0.</p>
    pub fn set_storage_location(mut self, input: ::std::option::Option<crate::types::S3Location>) -> Self {
        self.storage_location = input;
        self
    }
    /// <p>Information indicating where your game build files are stored. Use this parameter only when creating a build with files stored in an Amazon S3 bucket that you own. The storage location must specify an Amazon S3 bucket name and key. The location must also specify a role ARN that you set up to allow Amazon GameLift Servers to access your Amazon S3 bucket. The S3 bucket and your new build must be in the same Region.</p>
    /// <p>If a <code>StorageLocation</code> is specified, the size of your file can be found in your Amazon S3 bucket. Amazon GameLift Servers will report a <code>SizeOnDisk</code> of 0.</p>
    pub fn get_storage_location(&self) -> &::std::option::Option<crate::types::S3Location> {
        &self.storage_location
    }
    /// <p>The operating system that your game server binaries run on. This value determines the type of fleet resources that you use for this build. If your game build contains multiple executables, they all must run on the same operating system. You must specify a valid operating system in this request. There is no default value. You can't change a build's operating system later.</p><note>
    /// <p>Amazon Linux 2 (AL2) will reach end of support on 6/30/2025. See more details in the <a href="http://aws.amazon.com/amazon-linux-2/faqs/">Amazon Linux 2 FAQs</a>. For game servers that are hosted on AL2 and use server SDK version 4.x for Amazon GameLift Servers, first update the game server build to server SDK 5.x, and then deploy to AL2023 instances. See <a href="https://docs.aws.amazon.com/gamelift/latest/developerguide/reference-serversdk5-migration.html"> Migrate to server SDK version 5.</a></p>
    /// </note>
    pub fn operating_system(mut self, input: crate::types::OperatingSystem) -> Self {
        self.operating_system = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operating system that your game server binaries run on. This value determines the type of fleet resources that you use for this build. If your game build contains multiple executables, they all must run on the same operating system. You must specify a valid operating system in this request. There is no default value. You can't change a build's operating system later.</p><note>
    /// <p>Amazon Linux 2 (AL2) will reach end of support on 6/30/2025. See more details in the <a href="http://aws.amazon.com/amazon-linux-2/faqs/">Amazon Linux 2 FAQs</a>. For game servers that are hosted on AL2 and use server SDK version 4.x for Amazon GameLift Servers, first update the game server build to server SDK 5.x, and then deploy to AL2023 instances. See <a href="https://docs.aws.amazon.com/gamelift/latest/developerguide/reference-serversdk5-migration.html"> Migrate to server SDK version 5.</a></p>
    /// </note>
    pub fn set_operating_system(mut self, input: ::std::option::Option<crate::types::OperatingSystem>) -> Self {
        self.operating_system = input;
        self
    }
    /// <p>The operating system that your game server binaries run on. This value determines the type of fleet resources that you use for this build. If your game build contains multiple executables, they all must run on the same operating system. You must specify a valid operating system in this request. There is no default value. You can't change a build's operating system later.</p><note>
    /// <p>Amazon Linux 2 (AL2) will reach end of support on 6/30/2025. See more details in the <a href="http://aws.amazon.com/amazon-linux-2/faqs/">Amazon Linux 2 FAQs</a>. For game servers that are hosted on AL2 and use server SDK version 4.x for Amazon GameLift Servers, first update the game server build to server SDK 5.x, and then deploy to AL2023 instances. See <a href="https://docs.aws.amazon.com/gamelift/latest/developerguide/reference-serversdk5-migration.html"> Migrate to server SDK version 5.</a></p>
    /// </note>
    pub fn get_operating_system(&self) -> &::std::option::Option<crate::types::OperatingSystem> {
        &self.operating_system
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A list of labels to assign to the new build resource. Tags are developer defined key-value pairs. Tagging Amazon Web Services resources are useful for resource management, access management and cost allocation. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html"> Tagging Amazon Web Services Resources</a> in the <i>Amazon Web Services General Reference</i>. Once the resource is created, you can use <a href="https://docs.aws.amazon.com/gamelift/latest/apireference/API_TagResource.html">TagResource</a>, <a href="https://docs.aws.amazon.com/gamelift/latest/apireference/API_UntagResource.html">UntagResource</a>, and <a href="https://docs.aws.amazon.com/gamelift/latest/apireference/API_ListTagsForResource.html">ListTagsForResource</a> to add, remove, and view tags. The maximum tag limit may be lower than stated. See the Amazon Web Services General Reference for actual tagging limits.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of labels to assign to the new build resource. Tags are developer defined key-value pairs. Tagging Amazon Web Services resources are useful for resource management, access management and cost allocation. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html"> Tagging Amazon Web Services Resources</a> in the <i>Amazon Web Services General Reference</i>. Once the resource is created, you can use <a href="https://docs.aws.amazon.com/gamelift/latest/apireference/API_TagResource.html">TagResource</a>, <a href="https://docs.aws.amazon.com/gamelift/latest/apireference/API_UntagResource.html">UntagResource</a>, and <a href="https://docs.aws.amazon.com/gamelift/latest/apireference/API_ListTagsForResource.html">ListTagsForResource</a> to add, remove, and view tags. The maximum tag limit may be lower than stated. See the Amazon Web Services General Reference for actual tagging limits.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A list of labels to assign to the new build resource. Tags are developer defined key-value pairs. Tagging Amazon Web Services resources are useful for resource management, access management and cost allocation. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html"> Tagging Amazon Web Services Resources</a> in the <i>Amazon Web Services General Reference</i>. Once the resource is created, you can use <a href="https://docs.aws.amazon.com/gamelift/latest/apireference/API_TagResource.html">TagResource</a>, <a href="https://docs.aws.amazon.com/gamelift/latest/apireference/API_UntagResource.html">UntagResource</a>, and <a href="https://docs.aws.amazon.com/gamelift/latest/apireference/API_ListTagsForResource.html">ListTagsForResource</a> to add, remove, and view tags. The maximum tag limit may be lower than stated. See the Amazon Web Services General Reference for actual tagging limits.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>A server SDK version you used when integrating your game server build with Amazon GameLift Servers. For more information see <a href="https://docs.aws.amazon.com/gamelift/latest/developerguide/integration-custom-intro.html">Integrate games with custom game servers</a>. By default Amazon GameLift Servers sets this value to <code>4.0.2</code>.</p>
    pub fn server_sdk_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.server_sdk_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A server SDK version you used when integrating your game server build with Amazon GameLift Servers. For more information see <a href="https://docs.aws.amazon.com/gamelift/latest/developerguide/integration-custom-intro.html">Integrate games with custom game servers</a>. By default Amazon GameLift Servers sets this value to <code>4.0.2</code>.</p>
    pub fn set_server_sdk_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.server_sdk_version = input;
        self
    }
    /// <p>A server SDK version you used when integrating your game server build with Amazon GameLift Servers. For more information see <a href="https://docs.aws.amazon.com/gamelift/latest/developerguide/integration-custom-intro.html">Integrate games with custom game servers</a>. By default Amazon GameLift Servers sets this value to <code>4.0.2</code>.</p>
    pub fn get_server_sdk_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.server_sdk_version
    }
    /// Consumes the builder and constructs a [`CreateBuildInput`](crate::operation::create_build::CreateBuildInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::create_build::CreateBuildInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_build::CreateBuildInput {
            name: self.name,
            version: self.version,
            storage_location: self.storage_location,
            operating_system: self.operating_system,
            tags: self.tags,
            server_sdk_version: self.server_sdk_version,
        })
    }
}
