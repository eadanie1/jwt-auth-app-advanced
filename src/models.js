import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  role: { type: String, enum: ['admin', 'editor', 'viewer'] }
});

export const User = mongoose.model('User', userSchema);

const postSchema = new mongoose.Schema({
  title: String,
  content: String,
  author: String
});

export const Post = mongoose.model('Post', postSchema);

const adminSchema = new mongoose.Schema({
  all_users: Number,
  total_no_of_dbs: Number,
  cloud_host: String
});

export const Admin = mongoose.model('Admin', adminSchema);

const editorSchema = new mongoose.Schema({
  no_of_logged_in_users: Number,
  no_of_inactive_users: Number,
  encountered_runtime_errors: Number
});

export const Editor = mongoose.model('Editor', editorSchema);

const viewerSchema = new mongoose.Schema({
  posts: String,
  new_features: String
});

export const Viewer = mongoose.model('Viewer', viewerSchema);

const refresh_tokenSchema = new mongoose.Schema({
  refreshToken: String
});

export const Refresh_Token = mongoose.model('Refresh_Token', refresh_tokenSchema);