// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Creates and submits a request to start a remote access session.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateRemoteAccessSessionInput {
    /// <p>The Amazon Resource Name (ARN) of the project for which you want to create a remote access session.</p>
    pub project_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the device for which you want to create a remote access session.</p>
    pub device_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the device instance for which you want to create a remote access session.</p>
    pub instance_arn: ::std::option::Option<::std::string::String>,
    /// <p>Ignored. The public key of the <code>ssh</code> key pair you want to use for connecting to remote devices in your remote debugging session. This key is required only if <code>remoteDebugEnabled</code> is set to <code>true</code>.</p>
    /// <p>Remote debugging is <a href="https://docs.aws.amazon.com/devicefarm/latest/developerguide/history.html">no longer supported</a>.</p>
    pub ssh_public_key: ::std::option::Option<::std::string::String>,
    /// <p>Set to <code>true</code> if you want to access devices remotely for debugging in your remote access session.</p>
    /// <p>Remote debugging is <a href="https://docs.aws.amazon.com/devicefarm/latest/developerguide/history.html">no longer supported</a>.</p>
    pub remote_debug_enabled: ::std::option::Option<bool>,
    /// <p>Set to <code>true</code> to enable remote recording for the remote access session.</p>
    pub remote_record_enabled: ::std::option::Option<bool>,
    /// <p>The Amazon Resource Name (ARN) for the app to be recorded in the remote access session.</p>
    pub remote_record_app_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the remote access session to create.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Unique identifier for the client. If you want access to multiple devices on the same client, you should pass the same <code>clientId</code> value in each call to <code>CreateRemoteAccessSession</code>. This identifier is required only if <code>remoteDebugEnabled</code> is set to <code>true</code>.</p>
    /// <p>Remote debugging is <a href="https://docs.aws.amazon.com/devicefarm/latest/developerguide/history.html">no longer supported</a>.</p>
    pub client_id: ::std::option::Option<::std::string::String>,
    /// <p>The configuration information for the remote access session request.</p>
    pub configuration: ::std::option::Option<crate::types::CreateRemoteAccessSessionConfiguration>,
    /// <p>The interaction mode of the remote access session. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>INTERACTIVE: You can interact with the iOS device by viewing, touching, and rotating the screen. You cannot run XCUITest framework-based tests in this mode.</p></li>
    /// <li>
    /// <p>NO_VIDEO: You are connected to the device, but cannot interact with it or view the screen. This mode has the fastest test execution speed. You can run XCUITest framework-based tests in this mode.</p></li>
    /// <li>
    /// <p>VIDEO_ONLY: You can view the screen, but cannot touch or rotate it. You can run XCUITest framework-based tests and watch the screen in this mode.</p></li>
    /// </ul>
    pub interaction_mode: ::std::option::Option<crate::types::InteractionMode>,
    /// <p>When set to <code>true</code>, for private devices, Device Farm does not sign your app again. For public devices, Device Farm always signs your apps again.</p>
    /// <p>For more information on how Device Farm modifies your uploads during tests, see <a href="http://aws.amazon.com/device-farm/faqs/">Do you modify my app?</a></p>
    pub skip_app_resign: ::std::option::Option<bool>,
}
impl CreateRemoteAccessSessionInput {
    /// <p>The Amazon Resource Name (ARN) of the project for which you want to create a remote access session.</p>
    pub fn project_arn(&self) -> ::std::option::Option<&str> {
        self.project_arn.as_deref()
    }
    /// <p>The ARN of the device for which you want to create a remote access session.</p>
    pub fn device_arn(&self) -> ::std::option::Option<&str> {
        self.device_arn.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the device instance for which you want to create a remote access session.</p>
    pub fn instance_arn(&self) -> ::std::option::Option<&str> {
        self.instance_arn.as_deref()
    }
    /// <p>Ignored. The public key of the <code>ssh</code> key pair you want to use for connecting to remote devices in your remote debugging session. This key is required only if <code>remoteDebugEnabled</code> is set to <code>true</code>.</p>
    /// <p>Remote debugging is <a href="https://docs.aws.amazon.com/devicefarm/latest/developerguide/history.html">no longer supported</a>.</p>
    pub fn ssh_public_key(&self) -> ::std::option::Option<&str> {
        self.ssh_public_key.as_deref()
    }
    /// <p>Set to <code>true</code> if you want to access devices remotely for debugging in your remote access session.</p>
    /// <p>Remote debugging is <a href="https://docs.aws.amazon.com/devicefarm/latest/developerguide/history.html">no longer supported</a>.</p>
    pub fn remote_debug_enabled(&self) -> ::std::option::Option<bool> {
        self.remote_debug_enabled
    }
    /// <p>Set to <code>true</code> to enable remote recording for the remote access session.</p>
    pub fn remote_record_enabled(&self) -> ::std::option::Option<bool> {
        self.remote_record_enabled
    }
    /// <p>The Amazon Resource Name (ARN) for the app to be recorded in the remote access session.</p>
    pub fn remote_record_app_arn(&self) -> ::std::option::Option<&str> {
        self.remote_record_app_arn.as_deref()
    }
    /// <p>The name of the remote access session to create.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Unique identifier for the client. If you want access to multiple devices on the same client, you should pass the same <code>clientId</code> value in each call to <code>CreateRemoteAccessSession</code>. This identifier is required only if <code>remoteDebugEnabled</code> is set to <code>true</code>.</p>
    /// <p>Remote debugging is <a href="https://docs.aws.amazon.com/devicefarm/latest/developerguide/history.html">no longer supported</a>.</p>
    pub fn client_id(&self) -> ::std::option::Option<&str> {
        self.client_id.as_deref()
    }
    /// <p>The configuration information for the remote access session request.</p>
    pub fn configuration(&self) -> ::std::option::Option<&crate::types::CreateRemoteAccessSessionConfiguration> {
        self.configuration.as_ref()
    }
    /// <p>The interaction mode of the remote access session. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>INTERACTIVE: You can interact with the iOS device by viewing, touching, and rotating the screen. You cannot run XCUITest framework-based tests in this mode.</p></li>
    /// <li>
    /// <p>NO_VIDEO: You are connected to the device, but cannot interact with it or view the screen. This mode has the fastest test execution speed. You can run XCUITest framework-based tests in this mode.</p></li>
    /// <li>
    /// <p>VIDEO_ONLY: You can view the screen, but cannot touch or rotate it. You can run XCUITest framework-based tests and watch the screen in this mode.</p></li>
    /// </ul>
    pub fn interaction_mode(&self) -> ::std::option::Option<&crate::types::InteractionMode> {
        self.interaction_mode.as_ref()
    }
    /// <p>When set to <code>true</code>, for private devices, Device Farm does not sign your app again. For public devices, Device Farm always signs your apps again.</p>
    /// <p>For more information on how Device Farm modifies your uploads during tests, see <a href="http://aws.amazon.com/device-farm/faqs/">Do you modify my app?</a></p>
    pub fn skip_app_resign(&self) -> ::std::option::Option<bool> {
        self.skip_app_resign
    }
}
impl CreateRemoteAccessSessionInput {
    /// Creates a new builder-style object to manufacture [`CreateRemoteAccessSessionInput`](crate::operation::create_remote_access_session::CreateRemoteAccessSessionInput).
    pub fn builder() -> crate::operation::create_remote_access_session::builders::CreateRemoteAccessSessionInputBuilder {
        crate::operation::create_remote_access_session::builders::CreateRemoteAccessSessionInputBuilder::default()
    }
}

/// A builder for [`CreateRemoteAccessSessionInput`](crate::operation::create_remote_access_session::CreateRemoteAccessSessionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateRemoteAccessSessionInputBuilder {
    pub(crate) project_arn: ::std::option::Option<::std::string::String>,
    pub(crate) device_arn: ::std::option::Option<::std::string::String>,
    pub(crate) instance_arn: ::std::option::Option<::std::string::String>,
    pub(crate) ssh_public_key: ::std::option::Option<::std::string::String>,
    pub(crate) remote_debug_enabled: ::std::option::Option<bool>,
    pub(crate) remote_record_enabled: ::std::option::Option<bool>,
    pub(crate) remote_record_app_arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) client_id: ::std::option::Option<::std::string::String>,
    pub(crate) configuration: ::std::option::Option<crate::types::CreateRemoteAccessSessionConfiguration>,
    pub(crate) interaction_mode: ::std::option::Option<crate::types::InteractionMode>,
    pub(crate) skip_app_resign: ::std::option::Option<bool>,
}
impl CreateRemoteAccessSessionInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the project for which you want to create a remote access session.</p>
    /// This field is required.
    pub fn project_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.project_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the project for which you want to create a remote access session.</p>
    pub fn set_project_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.project_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the project for which you want to create a remote access session.</p>
    pub fn get_project_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.project_arn
    }
    /// <p>The ARN of the device for which you want to create a remote access session.</p>
    /// This field is required.
    pub fn device_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.device_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the device for which you want to create a remote access session.</p>
    pub fn set_device_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.device_arn = input;
        self
    }
    /// <p>The ARN of the device for which you want to create a remote access session.</p>
    pub fn get_device_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.device_arn
    }
    /// <p>The Amazon Resource Name (ARN) of the device instance for which you want to create a remote access session.</p>
    pub fn instance_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the device instance for which you want to create a remote access session.</p>
    pub fn set_instance_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the device instance for which you want to create a remote access session.</p>
    pub fn get_instance_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_arn
    }
    /// <p>Ignored. The public key of the <code>ssh</code> key pair you want to use for connecting to remote devices in your remote debugging session. This key is required only if <code>remoteDebugEnabled</code> is set to <code>true</code>.</p>
    /// <p>Remote debugging is <a href="https://docs.aws.amazon.com/devicefarm/latest/developerguide/history.html">no longer supported</a>.</p>
    pub fn ssh_public_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ssh_public_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Ignored. The public key of the <code>ssh</code> key pair you want to use for connecting to remote devices in your remote debugging session. This key is required only if <code>remoteDebugEnabled</code> is set to <code>true</code>.</p>
    /// <p>Remote debugging is <a href="https://docs.aws.amazon.com/devicefarm/latest/developerguide/history.html">no longer supported</a>.</p>
    pub fn set_ssh_public_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ssh_public_key = input;
        self
    }
    /// <p>Ignored. The public key of the <code>ssh</code> key pair you want to use for connecting to remote devices in your remote debugging session. This key is required only if <code>remoteDebugEnabled</code> is set to <code>true</code>.</p>
    /// <p>Remote debugging is <a href="https://docs.aws.amazon.com/devicefarm/latest/developerguide/history.html">no longer supported</a>.</p>
    pub fn get_ssh_public_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.ssh_public_key
    }
    /// <p>Set to <code>true</code> if you want to access devices remotely for debugging in your remote access session.</p>
    /// <p>Remote debugging is <a href="https://docs.aws.amazon.com/devicefarm/latest/developerguide/history.html">no longer supported</a>.</p>
    pub fn remote_debug_enabled(mut self, input: bool) -> Self {
        self.remote_debug_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Set to <code>true</code> if you want to access devices remotely for debugging in your remote access session.</p>
    /// <p>Remote debugging is <a href="https://docs.aws.amazon.com/devicefarm/latest/developerguide/history.html">no longer supported</a>.</p>
    pub fn set_remote_debug_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.remote_debug_enabled = input;
        self
    }
    /// <p>Set to <code>true</code> if you want to access devices remotely for debugging in your remote access session.</p>
    /// <p>Remote debugging is <a href="https://docs.aws.amazon.com/devicefarm/latest/developerguide/history.html">no longer supported</a>.</p>
    pub fn get_remote_debug_enabled(&self) -> &::std::option::Option<bool> {
        &self.remote_debug_enabled
    }
    /// <p>Set to <code>true</code> to enable remote recording for the remote access session.</p>
    pub fn remote_record_enabled(mut self, input: bool) -> Self {
        self.remote_record_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Set to <code>true</code> to enable remote recording for the remote access session.</p>
    pub fn set_remote_record_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.remote_record_enabled = input;
        self
    }
    /// <p>Set to <code>true</code> to enable remote recording for the remote access session.</p>
    pub fn get_remote_record_enabled(&self) -> &::std::option::Option<bool> {
        &self.remote_record_enabled
    }
    /// <p>The Amazon Resource Name (ARN) for the app to be recorded in the remote access session.</p>
    pub fn remote_record_app_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.remote_record_app_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the app to be recorded in the remote access session.</p>
    pub fn set_remote_record_app_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.remote_record_app_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the app to be recorded in the remote access session.</p>
    pub fn get_remote_record_app_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.remote_record_app_arn
    }
    /// <p>The name of the remote access session to create.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the remote access session to create.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the remote access session to create.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Unique identifier for the client. If you want access to multiple devices on the same client, you should pass the same <code>clientId</code> value in each call to <code>CreateRemoteAccessSession</code>. This identifier is required only if <code>remoteDebugEnabled</code> is set to <code>true</code>.</p>
    /// <p>Remote debugging is <a href="https://docs.aws.amazon.com/devicefarm/latest/developerguide/history.html">no longer supported</a>.</p>
    pub fn client_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique identifier for the client. If you want access to multiple devices on the same client, you should pass the same <code>clientId</code> value in each call to <code>CreateRemoteAccessSession</code>. This identifier is required only if <code>remoteDebugEnabled</code> is set to <code>true</code>.</p>
    /// <p>Remote debugging is <a href="https://docs.aws.amazon.com/devicefarm/latest/developerguide/history.html">no longer supported</a>.</p>
    pub fn set_client_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_id = input;
        self
    }
    /// <p>Unique identifier for the client. If you want access to multiple devices on the same client, you should pass the same <code>clientId</code> value in each call to <code>CreateRemoteAccessSession</code>. This identifier is required only if <code>remoteDebugEnabled</code> is set to <code>true</code>.</p>
    /// <p>Remote debugging is <a href="https://docs.aws.amazon.com/devicefarm/latest/developerguide/history.html">no longer supported</a>.</p>
    pub fn get_client_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_id
    }
    /// <p>The configuration information for the remote access session request.</p>
    pub fn configuration(mut self, input: crate::types::CreateRemoteAccessSessionConfiguration) -> Self {
        self.configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration information for the remote access session request.</p>
    pub fn set_configuration(mut self, input: ::std::option::Option<crate::types::CreateRemoteAccessSessionConfiguration>) -> Self {
        self.configuration = input;
        self
    }
    /// <p>The configuration information for the remote access session request.</p>
    pub fn get_configuration(&self) -> &::std::option::Option<crate::types::CreateRemoteAccessSessionConfiguration> {
        &self.configuration
    }
    /// <p>The interaction mode of the remote access session. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>INTERACTIVE: You can interact with the iOS device by viewing, touching, and rotating the screen. You cannot run XCUITest framework-based tests in this mode.</p></li>
    /// <li>
    /// <p>NO_VIDEO: You are connected to the device, but cannot interact with it or view the screen. This mode has the fastest test execution speed. You can run XCUITest framework-based tests in this mode.</p></li>
    /// <li>
    /// <p>VIDEO_ONLY: You can view the screen, but cannot touch or rotate it. You can run XCUITest framework-based tests and watch the screen in this mode.</p></li>
    /// </ul>
    pub fn interaction_mode(mut self, input: crate::types::InteractionMode) -> Self {
        self.interaction_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>The interaction mode of the remote access session. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>INTERACTIVE: You can interact with the iOS device by viewing, touching, and rotating the screen. You cannot run XCUITest framework-based tests in this mode.</p></li>
    /// <li>
    /// <p>NO_VIDEO: You are connected to the device, but cannot interact with it or view the screen. This mode has the fastest test execution speed. You can run XCUITest framework-based tests in this mode.</p></li>
    /// <li>
    /// <p>VIDEO_ONLY: You can view the screen, but cannot touch or rotate it. You can run XCUITest framework-based tests and watch the screen in this mode.</p></li>
    /// </ul>
    pub fn set_interaction_mode(mut self, input: ::std::option::Option<crate::types::InteractionMode>) -> Self {
        self.interaction_mode = input;
        self
    }
    /// <p>The interaction mode of the remote access session. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>INTERACTIVE: You can interact with the iOS device by viewing, touching, and rotating the screen. You cannot run XCUITest framework-based tests in this mode.</p></li>
    /// <li>
    /// <p>NO_VIDEO: You are connected to the device, but cannot interact with it or view the screen. This mode has the fastest test execution speed. You can run XCUITest framework-based tests in this mode.</p></li>
    /// <li>
    /// <p>VIDEO_ONLY: You can view the screen, but cannot touch or rotate it. You can run XCUITest framework-based tests and watch the screen in this mode.</p></li>
    /// </ul>
    pub fn get_interaction_mode(&self) -> &::std::option::Option<crate::types::InteractionMode> {
        &self.interaction_mode
    }
    /// <p>When set to <code>true</code>, for private devices, Device Farm does not sign your app again. For public devices, Device Farm always signs your apps again.</p>
    /// <p>For more information on how Device Farm modifies your uploads during tests, see <a href="http://aws.amazon.com/device-farm/faqs/">Do you modify my app?</a></p>
    pub fn skip_app_resign(mut self, input: bool) -> Self {
        self.skip_app_resign = ::std::option::Option::Some(input);
        self
    }
    /// <p>When set to <code>true</code>, for private devices, Device Farm does not sign your app again. For public devices, Device Farm always signs your apps again.</p>
    /// <p>For more information on how Device Farm modifies your uploads during tests, see <a href="http://aws.amazon.com/device-farm/faqs/">Do you modify my app?</a></p>
    pub fn set_skip_app_resign(mut self, input: ::std::option::Option<bool>) -> Self {
        self.skip_app_resign = input;
        self
    }
    /// <p>When set to <code>true</code>, for private devices, Device Farm does not sign your app again. For public devices, Device Farm always signs your apps again.</p>
    /// <p>For more information on how Device Farm modifies your uploads during tests, see <a href="http://aws.amazon.com/device-farm/faqs/">Do you modify my app?</a></p>
    pub fn get_skip_app_resign(&self) -> &::std::option::Option<bool> {
        &self.skip_app_resign
    }
    /// Consumes the builder and constructs a [`CreateRemoteAccessSessionInput`](crate::operation::create_remote_access_session::CreateRemoteAccessSessionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_remote_access_session::CreateRemoteAccessSessionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_remote_access_session::CreateRemoteAccessSessionInput {
            project_arn: self.project_arn,
            device_arn: self.device_arn,
            instance_arn: self.instance_arn,
            ssh_public_key: self.ssh_public_key,
            remote_debug_enabled: self.remote_debug_enabled,
            remote_record_enabled: self.remote_record_enabled,
            remote_record_app_arn: self.remote_record_app_arn,
            name: self.name,
            client_id: self.client_id,
            configuration: self.configuration,
            interaction_mode: self.interaction_mode,
            skip_app_resign: self.skip_app_resign,
        })
    }
}
