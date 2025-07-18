// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the settings for a one-time message that's sent directly to an endpoint through the GCM channel. The GCM channel enables Amazon Pinpoint to send messages to the Firebase Cloud Messaging (FCM), formerly Google Cloud Messaging (GCM), service.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GcmMessage {
    /// <p>The action to occur if the recipient taps the push notification. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>OPEN_APP - Your app opens or it becomes the foreground app if it was sent to the background. This is the default action.</p></li>
    /// <li>
    /// <p>DEEP_LINK - Your app opens and displays a designated user interface in the app. This action uses the deep-linking features of the Android platform.</p></li>
    /// <li>
    /// <p>URL - The default mobile browser on the recipient's device opens and loads the web page at a URL that you specify.</p></li>
    /// </ul>
    pub action: ::std::option::Option<crate::types::Action>,
    /// <p>The body of the notification message.</p>
    pub body: ::std::option::Option<::std::string::String>,
    /// <p>An arbitrary string that identifies a group of messages that can be collapsed to ensure that only the last message is sent when delivery can resume. This helps avoid sending too many instances of the same messages when the recipient's device comes online again or becomes active.</p>
    /// <p>Amazon Pinpoint specifies this value in the Firebase Cloud Messaging (FCM) collapse_key parameter when it sends the notification message to FCM.</p>
    pub collapse_key: ::std::option::Option<::std::string::String>,
    /// <p>The JSON data payload to use for the push notification, if the notification is a silent push notification. This payload is added to the data.pinpoint.jsonBody object of the notification.</p>
    pub data: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The icon image name of the asset saved in your app.</p>
    pub icon_reference: ::std::option::Option<::std::string::String>,
    /// <p>The URL of the large icon image to display in the content view of the push notification.</p>
    pub image_icon_url: ::std::option::Option<::std::string::String>,
    /// <p>The URL of an image to display in the push notification.</p>
    pub image_url: ::std::option::Option<::std::string::String>,
    /// <p>The preferred authentication method, with valid values "KEY" or "TOKEN". If a value isn't provided then the <b>DefaultAuthenticationMethod</b> is used.</p>
    pub preferred_authentication_method: ::std::option::Option<::std::string::String>,
    /// <p>para&gt;normal – The notification might be delayed. Delivery is optimized for battery usage on the recipient's device. Use this value unless immediate delivery is required.</p>/listitem&gt;
    /// <li>
    /// <p>high – The notification is sent immediately and might wake a sleeping device.</p></li>/para&gt;
    /// <p>Amazon Pinpoint specifies this value in the FCM priority parameter when it sends the notification message to FCM.</p>
    /// <p>The equivalent values for Apple Push Notification service (APNs) are 5, for normal, and 10, for high. If you specify an APNs value for this property, Amazon Pinpoint accepts and converts the value to the corresponding FCM value.</p>
    pub priority: ::std::option::Option<::std::string::String>,
    /// <p>The raw, JSON-formatted string to use as the payload for the notification message. If specified, this value overrides all other content for the message.</p>
    pub raw_content: ::std::option::Option<::std::string::String>,
    /// <p>The package name of the application where registration tokens must match in order for the recipient to receive the message.</p>
    pub restricted_package_name: ::std::option::Option<::std::string::String>,
    /// <p>Specifies whether the notification is a silent push notification, which is a push notification that doesn't display on a recipient's device. Silent push notifications can be used for cases such as updating an app's configuration or supporting phone home functionality.</p>
    pub silent_push: ::std::option::Option<bool>,
    /// <p>The URL of the small icon image to display in the status bar and the content view of the push notification.</p>
    pub small_image_icon_url: ::std::option::Option<::std::string::String>,
    /// <p>The sound to play when the recipient receives the push notification. You can use the default stream or specify the file name of a sound resource that's bundled in your app. On an Android platform, the sound file must reside in /res/raw/.</p>
    pub sound: ::std::option::Option<::std::string::String>,
    /// <p>The default message variables to use in the notification message. You can override the default variables with individual address variables.</p>
    pub substitutions: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>>,
    /// <p>The amount of time, in seconds, that FCM should store and attempt to deliver the push notification, if the service is unable to deliver the notification the first time. If you don't specify this value, FCM defaults to the maximum value, which is 2,419,200 seconds (28 days).</p>
    /// <p>Amazon Pinpoint specifies this value in the FCM time_to_live parameter when it sends the notification message to FCM.</p>
    pub time_to_live: ::std::option::Option<i32>,
    /// <p>The title to display above the notification message on the recipient's device.</p>
    pub title: ::std::option::Option<::std::string::String>,
    /// <p>The URL to open in the recipient's default mobile browser, if a recipient taps the push notification and the value of the Action property is URL.</p>
    pub url: ::std::option::Option<::std::string::String>,
}
impl GcmMessage {
    /// <p>The action to occur if the recipient taps the push notification. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>OPEN_APP - Your app opens or it becomes the foreground app if it was sent to the background. This is the default action.</p></li>
    /// <li>
    /// <p>DEEP_LINK - Your app opens and displays a designated user interface in the app. This action uses the deep-linking features of the Android platform.</p></li>
    /// <li>
    /// <p>URL - The default mobile browser on the recipient's device opens and loads the web page at a URL that you specify.</p></li>
    /// </ul>
    pub fn action(&self) -> ::std::option::Option<&crate::types::Action> {
        self.action.as_ref()
    }
    /// <p>The body of the notification message.</p>
    pub fn body(&self) -> ::std::option::Option<&str> {
        self.body.as_deref()
    }
    /// <p>An arbitrary string that identifies a group of messages that can be collapsed to ensure that only the last message is sent when delivery can resume. This helps avoid sending too many instances of the same messages when the recipient's device comes online again or becomes active.</p>
    /// <p>Amazon Pinpoint specifies this value in the Firebase Cloud Messaging (FCM) collapse_key parameter when it sends the notification message to FCM.</p>
    pub fn collapse_key(&self) -> ::std::option::Option<&str> {
        self.collapse_key.as_deref()
    }
    /// <p>The JSON data payload to use for the push notification, if the notification is a silent push notification. This payload is added to the data.pinpoint.jsonBody object of the notification.</p>
    pub fn data(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.data.as_ref()
    }
    /// <p>The icon image name of the asset saved in your app.</p>
    pub fn icon_reference(&self) -> ::std::option::Option<&str> {
        self.icon_reference.as_deref()
    }
    /// <p>The URL of the large icon image to display in the content view of the push notification.</p>
    pub fn image_icon_url(&self) -> ::std::option::Option<&str> {
        self.image_icon_url.as_deref()
    }
    /// <p>The URL of an image to display in the push notification.</p>
    pub fn image_url(&self) -> ::std::option::Option<&str> {
        self.image_url.as_deref()
    }
    /// <p>The preferred authentication method, with valid values "KEY" or "TOKEN". If a value isn't provided then the <b>DefaultAuthenticationMethod</b> is used.</p>
    pub fn preferred_authentication_method(&self) -> ::std::option::Option<&str> {
        self.preferred_authentication_method.as_deref()
    }
    /// <p>para&gt;normal – The notification might be delayed. Delivery is optimized for battery usage on the recipient's device. Use this value unless immediate delivery is required.</p>/listitem&gt;
    /// <li>
    /// <p>high – The notification is sent immediately and might wake a sleeping device.</p></li>/para&gt;
    /// <p>Amazon Pinpoint specifies this value in the FCM priority parameter when it sends the notification message to FCM.</p>
    /// <p>The equivalent values for Apple Push Notification service (APNs) are 5, for normal, and 10, for high. If you specify an APNs value for this property, Amazon Pinpoint accepts and converts the value to the corresponding FCM value.</p>
    pub fn priority(&self) -> ::std::option::Option<&str> {
        self.priority.as_deref()
    }
    /// <p>The raw, JSON-formatted string to use as the payload for the notification message. If specified, this value overrides all other content for the message.</p>
    pub fn raw_content(&self) -> ::std::option::Option<&str> {
        self.raw_content.as_deref()
    }
    /// <p>The package name of the application where registration tokens must match in order for the recipient to receive the message.</p>
    pub fn restricted_package_name(&self) -> ::std::option::Option<&str> {
        self.restricted_package_name.as_deref()
    }
    /// <p>Specifies whether the notification is a silent push notification, which is a push notification that doesn't display on a recipient's device. Silent push notifications can be used for cases such as updating an app's configuration or supporting phone home functionality.</p>
    pub fn silent_push(&self) -> ::std::option::Option<bool> {
        self.silent_push
    }
    /// <p>The URL of the small icon image to display in the status bar and the content view of the push notification.</p>
    pub fn small_image_icon_url(&self) -> ::std::option::Option<&str> {
        self.small_image_icon_url.as_deref()
    }
    /// <p>The sound to play when the recipient receives the push notification. You can use the default stream or specify the file name of a sound resource that's bundled in your app. On an Android platform, the sound file must reside in /res/raw/.</p>
    pub fn sound(&self) -> ::std::option::Option<&str> {
        self.sound.as_deref()
    }
    /// <p>The default message variables to use in the notification message. You can override the default variables with individual address variables.</p>
    pub fn substitutions(
        &self,
    ) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>> {
        self.substitutions.as_ref()
    }
    /// <p>The amount of time, in seconds, that FCM should store and attempt to deliver the push notification, if the service is unable to deliver the notification the first time. If you don't specify this value, FCM defaults to the maximum value, which is 2,419,200 seconds (28 days).</p>
    /// <p>Amazon Pinpoint specifies this value in the FCM time_to_live parameter when it sends the notification message to FCM.</p>
    pub fn time_to_live(&self) -> ::std::option::Option<i32> {
        self.time_to_live
    }
    /// <p>The title to display above the notification message on the recipient's device.</p>
    pub fn title(&self) -> ::std::option::Option<&str> {
        self.title.as_deref()
    }
    /// <p>The URL to open in the recipient's default mobile browser, if a recipient taps the push notification and the value of the Action property is URL.</p>
    pub fn url(&self) -> ::std::option::Option<&str> {
        self.url.as_deref()
    }
}
impl GcmMessage {
    /// Creates a new builder-style object to manufacture [`GcmMessage`](crate::types::GcmMessage).
    pub fn builder() -> crate::types::builders::GcmMessageBuilder {
        crate::types::builders::GcmMessageBuilder::default()
    }
}

/// A builder for [`GcmMessage`](crate::types::GcmMessage).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GcmMessageBuilder {
    pub(crate) action: ::std::option::Option<crate::types::Action>,
    pub(crate) body: ::std::option::Option<::std::string::String>,
    pub(crate) collapse_key: ::std::option::Option<::std::string::String>,
    pub(crate) data: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) icon_reference: ::std::option::Option<::std::string::String>,
    pub(crate) image_icon_url: ::std::option::Option<::std::string::String>,
    pub(crate) image_url: ::std::option::Option<::std::string::String>,
    pub(crate) preferred_authentication_method: ::std::option::Option<::std::string::String>,
    pub(crate) priority: ::std::option::Option<::std::string::String>,
    pub(crate) raw_content: ::std::option::Option<::std::string::String>,
    pub(crate) restricted_package_name: ::std::option::Option<::std::string::String>,
    pub(crate) silent_push: ::std::option::Option<bool>,
    pub(crate) small_image_icon_url: ::std::option::Option<::std::string::String>,
    pub(crate) sound: ::std::option::Option<::std::string::String>,
    pub(crate) substitutions: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>>,
    pub(crate) time_to_live: ::std::option::Option<i32>,
    pub(crate) title: ::std::option::Option<::std::string::String>,
    pub(crate) url: ::std::option::Option<::std::string::String>,
}
impl GcmMessageBuilder {
    /// <p>The action to occur if the recipient taps the push notification. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>OPEN_APP - Your app opens or it becomes the foreground app if it was sent to the background. This is the default action.</p></li>
    /// <li>
    /// <p>DEEP_LINK - Your app opens and displays a designated user interface in the app. This action uses the deep-linking features of the Android platform.</p></li>
    /// <li>
    /// <p>URL - The default mobile browser on the recipient's device opens and loads the web page at a URL that you specify.</p></li>
    /// </ul>
    pub fn action(mut self, input: crate::types::Action) -> Self {
        self.action = ::std::option::Option::Some(input);
        self
    }
    /// <p>The action to occur if the recipient taps the push notification. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>OPEN_APP - Your app opens or it becomes the foreground app if it was sent to the background. This is the default action.</p></li>
    /// <li>
    /// <p>DEEP_LINK - Your app opens and displays a designated user interface in the app. This action uses the deep-linking features of the Android platform.</p></li>
    /// <li>
    /// <p>URL - The default mobile browser on the recipient's device opens and loads the web page at a URL that you specify.</p></li>
    /// </ul>
    pub fn set_action(mut self, input: ::std::option::Option<crate::types::Action>) -> Self {
        self.action = input;
        self
    }
    /// <p>The action to occur if the recipient taps the push notification. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>OPEN_APP - Your app opens or it becomes the foreground app if it was sent to the background. This is the default action.</p></li>
    /// <li>
    /// <p>DEEP_LINK - Your app opens and displays a designated user interface in the app. This action uses the deep-linking features of the Android platform.</p></li>
    /// <li>
    /// <p>URL - The default mobile browser on the recipient's device opens and loads the web page at a URL that you specify.</p></li>
    /// </ul>
    pub fn get_action(&self) -> &::std::option::Option<crate::types::Action> {
        &self.action
    }
    /// <p>The body of the notification message.</p>
    pub fn body(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.body = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The body of the notification message.</p>
    pub fn set_body(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.body = input;
        self
    }
    /// <p>The body of the notification message.</p>
    pub fn get_body(&self) -> &::std::option::Option<::std::string::String> {
        &self.body
    }
    /// <p>An arbitrary string that identifies a group of messages that can be collapsed to ensure that only the last message is sent when delivery can resume. This helps avoid sending too many instances of the same messages when the recipient's device comes online again or becomes active.</p>
    /// <p>Amazon Pinpoint specifies this value in the Firebase Cloud Messaging (FCM) collapse_key parameter when it sends the notification message to FCM.</p>
    pub fn collapse_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.collapse_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An arbitrary string that identifies a group of messages that can be collapsed to ensure that only the last message is sent when delivery can resume. This helps avoid sending too many instances of the same messages when the recipient's device comes online again or becomes active.</p>
    /// <p>Amazon Pinpoint specifies this value in the Firebase Cloud Messaging (FCM) collapse_key parameter when it sends the notification message to FCM.</p>
    pub fn set_collapse_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.collapse_key = input;
        self
    }
    /// <p>An arbitrary string that identifies a group of messages that can be collapsed to ensure that only the last message is sent when delivery can resume. This helps avoid sending too many instances of the same messages when the recipient's device comes online again or becomes active.</p>
    /// <p>Amazon Pinpoint specifies this value in the Firebase Cloud Messaging (FCM) collapse_key parameter when it sends the notification message to FCM.</p>
    pub fn get_collapse_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.collapse_key
    }
    /// Adds a key-value pair to `data`.
    ///
    /// To override the contents of this collection use [`set_data`](Self::set_data).
    ///
    /// <p>The JSON data payload to use for the push notification, if the notification is a silent push notification. This payload is added to the data.pinpoint.jsonBody object of the notification.</p>
    pub fn data(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.data.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.data = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The JSON data payload to use for the push notification, if the notification is a silent push notification. This payload is added to the data.pinpoint.jsonBody object of the notification.</p>
    pub fn set_data(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.data = input;
        self
    }
    /// <p>The JSON data payload to use for the push notification, if the notification is a silent push notification. This payload is added to the data.pinpoint.jsonBody object of the notification.</p>
    pub fn get_data(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.data
    }
    /// <p>The icon image name of the asset saved in your app.</p>
    pub fn icon_reference(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.icon_reference = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The icon image name of the asset saved in your app.</p>
    pub fn set_icon_reference(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.icon_reference = input;
        self
    }
    /// <p>The icon image name of the asset saved in your app.</p>
    pub fn get_icon_reference(&self) -> &::std::option::Option<::std::string::String> {
        &self.icon_reference
    }
    /// <p>The URL of the large icon image to display in the content view of the push notification.</p>
    pub fn image_icon_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image_icon_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URL of the large icon image to display in the content view of the push notification.</p>
    pub fn set_image_icon_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image_icon_url = input;
        self
    }
    /// <p>The URL of the large icon image to display in the content view of the push notification.</p>
    pub fn get_image_icon_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.image_icon_url
    }
    /// <p>The URL of an image to display in the push notification.</p>
    pub fn image_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URL of an image to display in the push notification.</p>
    pub fn set_image_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image_url = input;
        self
    }
    /// <p>The URL of an image to display in the push notification.</p>
    pub fn get_image_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.image_url
    }
    /// <p>The preferred authentication method, with valid values "KEY" or "TOKEN". If a value isn't provided then the <b>DefaultAuthenticationMethod</b> is used.</p>
    pub fn preferred_authentication_method(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.preferred_authentication_method = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The preferred authentication method, with valid values "KEY" or "TOKEN". If a value isn't provided then the <b>DefaultAuthenticationMethod</b> is used.</p>
    pub fn set_preferred_authentication_method(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.preferred_authentication_method = input;
        self
    }
    /// <p>The preferred authentication method, with valid values "KEY" or "TOKEN". If a value isn't provided then the <b>DefaultAuthenticationMethod</b> is used.</p>
    pub fn get_preferred_authentication_method(&self) -> &::std::option::Option<::std::string::String> {
        &self.preferred_authentication_method
    }
    /// <p>para&gt;normal – The notification might be delayed. Delivery is optimized for battery usage on the recipient's device. Use this value unless immediate delivery is required.</p>/listitem&gt;
    /// <li>
    /// <p>high – The notification is sent immediately and might wake a sleeping device.</p></li>/para&gt;
    /// <p>Amazon Pinpoint specifies this value in the FCM priority parameter when it sends the notification message to FCM.</p>
    /// <p>The equivalent values for Apple Push Notification service (APNs) are 5, for normal, and 10, for high. If you specify an APNs value for this property, Amazon Pinpoint accepts and converts the value to the corresponding FCM value.</p>
    pub fn priority(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.priority = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>para&gt;normal – The notification might be delayed. Delivery is optimized for battery usage on the recipient's device. Use this value unless immediate delivery is required.</p>/listitem&gt;
    /// <li>
    /// <p>high – The notification is sent immediately and might wake a sleeping device.</p></li>/para&gt;
    /// <p>Amazon Pinpoint specifies this value in the FCM priority parameter when it sends the notification message to FCM.</p>
    /// <p>The equivalent values for Apple Push Notification service (APNs) are 5, for normal, and 10, for high. If you specify an APNs value for this property, Amazon Pinpoint accepts and converts the value to the corresponding FCM value.</p>
    pub fn set_priority(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.priority = input;
        self
    }
    /// <p>para&gt;normal – The notification might be delayed. Delivery is optimized for battery usage on the recipient's device. Use this value unless immediate delivery is required.</p>/listitem&gt;
    /// <li>
    /// <p>high – The notification is sent immediately and might wake a sleeping device.</p></li>/para&gt;
    /// <p>Amazon Pinpoint specifies this value in the FCM priority parameter when it sends the notification message to FCM.</p>
    /// <p>The equivalent values for Apple Push Notification service (APNs) are 5, for normal, and 10, for high. If you specify an APNs value for this property, Amazon Pinpoint accepts and converts the value to the corresponding FCM value.</p>
    pub fn get_priority(&self) -> &::std::option::Option<::std::string::String> {
        &self.priority
    }
    /// <p>The raw, JSON-formatted string to use as the payload for the notification message. If specified, this value overrides all other content for the message.</p>
    pub fn raw_content(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.raw_content = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The raw, JSON-formatted string to use as the payload for the notification message. If specified, this value overrides all other content for the message.</p>
    pub fn set_raw_content(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.raw_content = input;
        self
    }
    /// <p>The raw, JSON-formatted string to use as the payload for the notification message. If specified, this value overrides all other content for the message.</p>
    pub fn get_raw_content(&self) -> &::std::option::Option<::std::string::String> {
        &self.raw_content
    }
    /// <p>The package name of the application where registration tokens must match in order for the recipient to receive the message.</p>
    pub fn restricted_package_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.restricted_package_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The package name of the application where registration tokens must match in order for the recipient to receive the message.</p>
    pub fn set_restricted_package_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.restricted_package_name = input;
        self
    }
    /// <p>The package name of the application where registration tokens must match in order for the recipient to receive the message.</p>
    pub fn get_restricted_package_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.restricted_package_name
    }
    /// <p>Specifies whether the notification is a silent push notification, which is a push notification that doesn't display on a recipient's device. Silent push notifications can be used for cases such as updating an app's configuration or supporting phone home functionality.</p>
    pub fn silent_push(mut self, input: bool) -> Self {
        self.silent_push = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the notification is a silent push notification, which is a push notification that doesn't display on a recipient's device. Silent push notifications can be used for cases such as updating an app's configuration or supporting phone home functionality.</p>
    pub fn set_silent_push(mut self, input: ::std::option::Option<bool>) -> Self {
        self.silent_push = input;
        self
    }
    /// <p>Specifies whether the notification is a silent push notification, which is a push notification that doesn't display on a recipient's device. Silent push notifications can be used for cases such as updating an app's configuration or supporting phone home functionality.</p>
    pub fn get_silent_push(&self) -> &::std::option::Option<bool> {
        &self.silent_push
    }
    /// <p>The URL of the small icon image to display in the status bar and the content view of the push notification.</p>
    pub fn small_image_icon_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.small_image_icon_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URL of the small icon image to display in the status bar and the content view of the push notification.</p>
    pub fn set_small_image_icon_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.small_image_icon_url = input;
        self
    }
    /// <p>The URL of the small icon image to display in the status bar and the content view of the push notification.</p>
    pub fn get_small_image_icon_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.small_image_icon_url
    }
    /// <p>The sound to play when the recipient receives the push notification. You can use the default stream or specify the file name of a sound resource that's bundled in your app. On an Android platform, the sound file must reside in /res/raw/.</p>
    pub fn sound(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sound = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The sound to play when the recipient receives the push notification. You can use the default stream or specify the file name of a sound resource that's bundled in your app. On an Android platform, the sound file must reside in /res/raw/.</p>
    pub fn set_sound(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sound = input;
        self
    }
    /// <p>The sound to play when the recipient receives the push notification. You can use the default stream or specify the file name of a sound resource that's bundled in your app. On an Android platform, the sound file must reside in /res/raw/.</p>
    pub fn get_sound(&self) -> &::std::option::Option<::std::string::String> {
        &self.sound
    }
    /// Adds a key-value pair to `substitutions`.
    ///
    /// To override the contents of this collection use [`set_substitutions`](Self::set_substitutions).
    ///
    /// <p>The default message variables to use in the notification message. You can override the default variables with individual address variables.</p>
    pub fn substitutions(mut self, k: impl ::std::convert::Into<::std::string::String>, v: ::std::vec::Vec<::std::string::String>) -> Self {
        let mut hash_map = self.substitutions.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.substitutions = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The default message variables to use in the notification message. You can override the default variables with individual address variables.</p>
    pub fn set_substitutions(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>>,
    ) -> Self {
        self.substitutions = input;
        self
    }
    /// <p>The default message variables to use in the notification message. You can override the default variables with individual address variables.</p>
    pub fn get_substitutions(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>> {
        &self.substitutions
    }
    /// <p>The amount of time, in seconds, that FCM should store and attempt to deliver the push notification, if the service is unable to deliver the notification the first time. If you don't specify this value, FCM defaults to the maximum value, which is 2,419,200 seconds (28 days).</p>
    /// <p>Amazon Pinpoint specifies this value in the FCM time_to_live parameter when it sends the notification message to FCM.</p>
    pub fn time_to_live(mut self, input: i32) -> Self {
        self.time_to_live = ::std::option::Option::Some(input);
        self
    }
    /// <p>The amount of time, in seconds, that FCM should store and attempt to deliver the push notification, if the service is unable to deliver the notification the first time. If you don't specify this value, FCM defaults to the maximum value, which is 2,419,200 seconds (28 days).</p>
    /// <p>Amazon Pinpoint specifies this value in the FCM time_to_live parameter when it sends the notification message to FCM.</p>
    pub fn set_time_to_live(mut self, input: ::std::option::Option<i32>) -> Self {
        self.time_to_live = input;
        self
    }
    /// <p>The amount of time, in seconds, that FCM should store and attempt to deliver the push notification, if the service is unable to deliver the notification the first time. If you don't specify this value, FCM defaults to the maximum value, which is 2,419,200 seconds (28 days).</p>
    /// <p>Amazon Pinpoint specifies this value in the FCM time_to_live parameter when it sends the notification message to FCM.</p>
    pub fn get_time_to_live(&self) -> &::std::option::Option<i32> {
        &self.time_to_live
    }
    /// <p>The title to display above the notification message on the recipient's device.</p>
    pub fn title(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.title = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The title to display above the notification message on the recipient's device.</p>
    pub fn set_title(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.title = input;
        self
    }
    /// <p>The title to display above the notification message on the recipient's device.</p>
    pub fn get_title(&self) -> &::std::option::Option<::std::string::String> {
        &self.title
    }
    /// <p>The URL to open in the recipient's default mobile browser, if a recipient taps the push notification and the value of the Action property is URL.</p>
    pub fn url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URL to open in the recipient's default mobile browser, if a recipient taps the push notification and the value of the Action property is URL.</p>
    pub fn set_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.url = input;
        self
    }
    /// <p>The URL to open in the recipient's default mobile browser, if a recipient taps the push notification and the value of the Action property is URL.</p>
    pub fn get_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.url
    }
    /// Consumes the builder and constructs a [`GcmMessage`](crate::types::GcmMessage).
    pub fn build(self) -> crate::types::GcmMessage {
        crate::types::GcmMessage {
            action: self.action,
            body: self.body,
            collapse_key: self.collapse_key,
            data: self.data,
            icon_reference: self.icon_reference,
            image_icon_url: self.image_icon_url,
            image_url: self.image_url,
            preferred_authentication_method: self.preferred_authentication_method,
            priority: self.priority,
            raw_content: self.raw_content,
            restricted_package_name: self.restricted_package_name,
            silent_push: self.silent_push,
            small_image_icon_url: self.small_image_icon_url,
            sound: self.sound,
            substitutions: self.substitutions,
            time_to_live: self.time_to_live,
            title: self.title,
            url: self.url,
        }
    }
}
