const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const app = express();

app.use(express.json());

mongoose.connect('mongodb+srv://CaioAdmin:Jason007891%40@key-api.5upx8.mongodb.net/?retryWrites=true&w=majority&appName=Key-API', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const KeySchema = new mongoose.Schema({
  value: String,
  type: String,
  hwid: String,
  expires: Date,
  valid: Boolean 
}, {
  versionKey: false
});

KeySchema.index({ value: 1 }, { unique: true });

const Key = mongoose.model('Key', KeySchema);


app.post('/generate', async (req, res) => {
  const { duration, type } = req.body;

  if (!duration || !type) {
    return res.status(400).json({ error: 'Duração e tipo são obrigatórios' });
  }

  if (isNaN(duration)) {
    return res.status(400).json({ error: 'Duração deve ser um número em horas' });
  }

  try {
    const keyValue = `${type.toUpperCase()}_${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
    const expires = new Date(Date.now() + (duration * 60 * 60 * 1000));

    const newKey = new Key({
      value: keyValue,
      type: type.toLowerCase(),
      hwid: '',
      expires: expires,
      valid: true 
    });

    await newKey.save();

    res.json({
      key: keyValue,
      expires: expires.toISOString(),
      duration_hours: duration,
      hwid: ''
    });

  } catch (error) {
    if (error.code === 11000) {
      return res.status(500).json({ error: 'Key duplicada, tente novamente' });
    }
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});


app.post('/associate', async (req, res) => {
  const { key, hwid } = req.body;

  if (!key || !hwid) {
    return res.status(400).json({ error: 'Key e HWID são obrigatórios' });
  }

  try {
    const hashedHwid = crypto.createHash('sha256').update(hwid).digest('hex');
    const keyData = await Key.findOne({ value: key });

    if (!keyData) {
      return res.status(404).json({ error: 'Key não encontrada' });
    }

    if (keyData.hwid && keyData.hwid !== '') {
      return res.status(400).json({ error: 'Key já associada a um HWID' });
    }

    keyData.hwid = hashedHwid;
    await keyData.save();

    res.json({ message: 'HWID associado com sucesso' });

  } catch (error) {
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});


app.post('/verify', async (req, res) => {
  const { key, hwid } = req.body;

  if (!key || !hwid) {
    return res.status(400).json({ 
      valid: false, 
      message: 'Key e HWID são obrigatórios' 
    });
  }

  try {
    const hashedHwid = crypto.createHash('sha256').update(hwid).digest('hex');
    const keyData = await Key.findOne({ value: key });

    if (!keyData) {
      return res.status(404).json({ 
        valid: false, 
        message: 'Key não encontrada' 
      });
    }

    if (keyData.hwid !== hashedHwid) {
      return res.status(403).json({ 
        valid: false, 
        message: 'HWID não corresponde à key' 
      });
    }

    if (!keyData.valid) {
      return res.status(403).json({ 
        valid: false, 
        message: 'Key inválida' 
      });
    }

    if (keyData.expires < new Date()) {
      return res.status(410).json({ 
        valid: false, 
        message: 'Key expirada' 
      });
    }

    res.json({
      valid: true,
      type: keyData.type,
      expires: keyData.expires,
      remaining: Math.ceil((keyData.expires - Date.now()) / (1000 * 60 * 60)) + ' horas'
    });

  } catch (error) {
    res.status(500).json({ 
      valid: false, 
      message: 'Erro na verificação' 
    });
  }
});


app.delete('/cleanup', async (req, res) => {
  try {
    const deletedKeys = await Key.deleteMany({ expires: { $lt: new Date() } });
    res.json({ message: `${deletedKeys.deletedCount} keys removidas` });

  } catch (error) {
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});


app.put('/setValidity', async (req, res) => {
  const { key, valid } = req.body;

  if (!key || typeof valid !== 'boolean') {
    return res.status(400).json({ error: 'Key e valid são obrigatórios e valid deve ser um booleano' });
  }

  try {
    const keyData = await Key.findOne({ value: key });

    if (!keyData) {
      return res.status(404).json({ error: 'Key não encontrada' });
    }

    keyData.valid = valid;
    await keyData.save();

    res.json({ message: `Key ${valid ? 'validada' : 'invalidada'} com sucesso` });

  } catch (error) {
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

app.listen(3000, () => console.log('Servidor rodando na porta 3000'));