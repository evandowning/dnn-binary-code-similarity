# DNN Binary Code Similarity Detection
This repo provides an implementation of the Gemini network for binary code similarity detection in [this paper](https://arxiv.org/abs/1708.06525).

## Prepration and Data
Unzip the data by running:
```
$ unzip data.zip
```

Create environment
```
$ mkvirtualenv gemini --python=python3
(gemini) $ pip install -r requirements.txt
```

## Extract features
```
$ python extract.py binja --bndb binary.bndb --output binary.json
```

## Model Implementation
The model is implemented in `graphnnSiamese.py`.

Run the following code to train the model:
```
$ python train.py
```
or run `python train.py -h` to check the optional arguments.

After training, run the following code to evaluate the model:
```
$ python eval.py
```
or run `python eval.py -h` to check the optional arguments.
